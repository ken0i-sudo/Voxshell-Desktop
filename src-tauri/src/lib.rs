pub mod ai;
pub mod audio;
pub mod db;
pub mod error;
pub mod executors;
pub mod ipc;
pub mod security;
pub mod state;
pub mod undo;

use db::connection::init_database;
use state::{AppState, SessionContext, SessionState};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db_path = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("VoxShell")
        .join("voxshell_v2.db");

    let conn = init_database(&db_path).expect("Failed to initialize VoxShell SQLite WAL database");

    let app_state = AppState {
        session: Arc::new(TokioMutex::new(SessionContext {
            current_state: SessionState::Idle,
            active_command_id: None,
            pending_dry_run: None,
            auth_timeout_handle: None,
        })),
        db: Arc::new(Mutex::new(conn)),
        audio_handle: Arc::new(TokioMutex::new(None)),
        active_cancel_token: Arc::new(TokioMutex::new(None)),
    };

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            ipc::commands::start_voice_session,
            ipc::commands::stop_and_process_voice,
            ipc::commands::submit_text_query,
            ipc::commands::authorize_and_execute,
            ipc::commands::cancel_command,
            ipc::commands::undo_command_ipc,
            ipc::commands::get_command_history,
            ipc::commands::set_api_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
