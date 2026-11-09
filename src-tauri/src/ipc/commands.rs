use crate::ai::keychain::{store_api_key, ApiProvider};
use crate::ai::llm_intent::VoxShellIntentPayload;
use crate::ai::stt::{transcribe_wav_buffer, SttProvider};
use crate::audio::capture::start_audio_capture;
use crate::error::VoxError;
use crate::executors::dry_run::{build_file_dry_run_with_bases, ValidatedFileDryRunPlan};
use crate::executors::file_ops::{execute_validated_file_plan, BatchExecutionReceipt};
use crate::security::sandbox::PathSandbox;
use crate::state::{AppState, SessionContext, SessionState};
use crate::undo::rollback::{undo_command, UndoReceipt};
use rusqlite::params;
use std::sync::Arc;
use std::time::Duration;
use tauri::State;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

pub const AUTH_TIMEOUT_SECS: u64 = 30;

/// Spawns a 30-second countdown timer that automatically cancels an unconfirmed dry-run preview.
fn spawn_auth_timeout_guard(
    session_arc: Arc<TokioMutex<SessionContext>>,
    expected_command_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(AUTH_TIMEOUT_SECS)).await;
        let mut session = session_arc.lock().await;
        if session.current_state == SessionState::AwaitingAuth
            && session.active_command_id.as_deref() == Some(expected_command_id.as_str())
        {
            session.current_state = SessionState::Cancelled;
            session.pending_dry_run = None;
            session.active_command_id = None;
        }
    })
}

#[tauri::command]
pub async fn start_voice_session(state: State<'_, AppState>) -> Result<String, VoxError> {
    let mut session = state.session.lock().await;
    if let Some(handle) = session.auth_timeout_handle.take() {
        handle.abort();
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    session.current_state = SessionState::Listening;
    session.active_command_id = Some(session_id.clone());

    let audio = start_audio_capture()?;
    let mut handle_lock = state.audio_handle.lock().await;
    *handle_lock = Some(audio);

    Ok(session_id)
}

#[tauri::command]
pub async fn stop_and_process_voice(
    _session_id: String,
    state: State<'_, AppState>,
) -> Result<ValidatedFileDryRunPlan, VoxError> {
    let wav_bytes = {
        let mut handle_lock = state.audio_handle.lock().await;
        if let Some(mut audio) = handle_lock.take() {
            audio.stop_and_get_wav()?
        } else {
            return Err(VoxError::SttSilence);
        }
    };

    {
        let mut session = state.session.lock().await;
        session.current_state = SessionState::Transcribing;
    }

    let stt_res = transcribe_wav_buffer(&wav_bytes, SttProvider::LocalWhisper, None).await?;
    process_transcript_into_dry_run(&stt_res.transcript, &state).await
}

#[tauri::command]
pub async fn submit_text_query(
    query: String,
    state: State<'_, AppState>,
) -> Result<ValidatedFileDryRunPlan, VoxError> {
    process_transcript_into_dry_run(&query, &state).await
}

async fn process_transcript_into_dry_run(
    transcript: &str,
    state: &State<'_, AppState>,
) -> Result<ValidatedFileDryRunPlan, VoxError> {
    let command_id = uuid::Uuid::new_v4().to_string();

    {
        let mut session = state.session.lock().await;
        if let Some(handle) = session.auth_timeout_handle.take() {
            handle.abort();
        }
        session.current_state = SessionState::IntentParsing;
        session.active_command_id = Some(command_id.clone());
    }

    let intent = VoxShellIntentPayload::from_natural_text_fallback(transcript);
    let file_req = intent
        .to_file_intent_request(&command_id, transcript)
        .ok_or_else(|| VoxError::SourceNotFound("Intent does not map to a file operation".into()))?;

    let sandbox = {
        let conn = state.db.lock().unwrap();
        PathSandbox::from_db(&conn)?
    };

    let src_dir = file_req
        .source_base_dir
        .and_then(|b| b.resolve_os_dir());
    let dst_dir = file_req
        .destination_base_dir
        .and_then(|b| b.resolve_os_dir());

    let plan = build_file_dry_run_with_bases(
        &sandbox,
        &file_req,
        src_dir.as_deref(),
        dst_dir.as_deref(),
    )?;

    let mut session = state.session.lock().await;
    session.current_state = SessionState::AwaitingAuth;
    session.pending_dry_run = Some(plan.clone());
    session.auth_timeout_handle = Some(spawn_auth_timeout_guard(
        Arc::clone(&state.session),
        command_id,
    ));

    Ok(plan)
}

#[tauri::command]
pub async fn authorize_and_execute(
    command_id: String,
    _auth_method: String,
    state: State<'_, AppState>,
) -> Result<BatchExecutionReceipt, VoxError> {
    let plan = {
        let mut session = state.session.lock().await;
        if let Some(handle) = session.auth_timeout_handle.take() {
            handle.abort();
        }
        let pending = session
            .pending_dry_run
            .take()
            .ok_or_else(|| VoxError::SourceNotFound("No pending dry-run plan found".into()))?;

        if pending.command_id != command_id {
            return Err(VoxError::SourceNotFound("Command ID mismatch".into()));
        }
        session.current_state = SessionState::Executing;
        pending
    };

    let cancel_token = CancellationToken::new();
    {
        let mut cancel_lock = state.active_cancel_token.lock().await;
        *cancel_lock = Some(cancel_token);
    }

    let receipt = {
        let mut conn = state.db.lock().unwrap();
        execute_validated_file_plan(&mut conn, &plan, false, None)?
    };

    let mut session = state.session.lock().await;
    session.current_state = if receipt.failed_count == 0 {
        SessionState::Completed
    } else if receipt.succeeded_count > 0 {
        SessionState::PartiallyCompleted
    } else {
        SessionState::Failed
    };

    Ok(receipt)
}

#[tauri::command]
pub async fn cancel_command(command_id: String, state: State<'_, AppState>) -> Result<(), VoxError> {
    {
        let mut cancel_lock = state.active_cancel_token.lock().await;
        if let Some(token) = cancel_lock.take() {
            token.cancel();
        }
    }

    {
        let mut session = state.session.lock().await;
        if let Some(handle) = session.auth_timeout_handle.take() {
            handle.abort();
        }
        session.current_state = SessionState::Cancelled;
        session.pending_dry_run = None;
    }

    let conn = state.db.lock().unwrap();
    conn.execute(
        "UPDATE command_logs SET execution_status = 'CANCELLED' WHERE id = ?1",
        params![command_id],
    )?;

    Ok(())
}

#[tauri::command]
pub async fn undo_command_ipc(
    command_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<UndoReceipt, VoxError> {
    let mut conn = state.db.lock().unwrap();
    undo_command(&mut conn, command_id.as_deref(), None)
}

#[tauri::command]
pub async fn get_command_history(
    limit: u32,
    offset: u32,
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, VoxError> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, raw_transcript, action_type, security_tier, execution_status, is_undoable, created_at_ms
         FROM command_logs ORDER BY created_at_ms DESC LIMIT ?1 OFFSET ?2",
    )?;

    let rows = stmt.query_map(params![limit, offset], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "raw_transcript": row.get::<_, String>(1)?,
            "action_type": row.get::<_, String>(2)?,
            "security_tier": row.get::<_, String>(3)?,
            "execution_status": row.get::<_, String>(4)?,
            "is_undoable": row.get::<_, i32>(5)? == 1,
            "created_at_ms": row.get::<_, i64>(6)?,
        }))
    })?;

    let history = rows.collect::<Result<Vec<_>, _>>()?;
    Ok(history)
}

#[tauri::command]
pub async fn set_api_credential(provider: ApiProvider, api_key: String) -> Result<(), VoxError> {
    store_api_key(provider, &api_key)
}
