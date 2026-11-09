use crate::audio::capture::AudioCaptureHandle;
use crate::executors::dry_run::ValidatedFileDryRunPlan;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Idle,
    Listening,
    Transcribing,
    IntentParsing,
    DryRunPreview,
    AwaitingAuth,
    Executing,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

pub struct SessionContext {
    pub current_state: SessionState,
    pub active_command_id: Option<String>,
    pub pending_dry_run: Option<ValidatedFileDryRunPlan>,
    pub auth_timeout_handle: Option<tokio::task::JoinHandle<()>>,
}

pub struct AppState {
    pub session: Arc<TokioMutex<SessionContext>>,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub audio_handle: Arc<TokioMutex<Option<AudioCaptureHandle>>>,
    pub active_cancel_token: Arc<TokioMutex<Option<CancellationToken>>>,
}
