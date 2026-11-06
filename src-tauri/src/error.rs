use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VoxError {
    #[error("Didn't catch that. Press Alt+Space and try again.")]
    SttSilence,

    #[error("Blocked for security: Path '{0}' is outside your allowed user folders.")]
    PathOutsideSandbox(String),

    #[error("Blocked for security: Relative path traversal ('..') is prohibited.")]
    PathTraversalDetected,

    #[error("Blocked for security: Modifying hidden dotfile or folder '{0}' is prohibited.")]
    HiddenDotfileBlocked(String),

    #[error("Security Guard: Moving or renaming executable/script file '{0}' is restricted.")]
    ExecutableGuard(String),

    #[error("Source file or directory not found: '{0}'.")]
    SourceNotFound(String),

    #[error("Batch exceeds the 500-file safety limit ({0} files matched).")]
    BatchLimitExceeded(usize),

    #[error("File '{0}' is currently open or locked by another application.")]
    FileLocked(String),

    #[error("Multiple packages matched '{0}'. Please select the exact package.")]
    WingetAmbiguous(String),

    #[error("Operation timed out after 180 seconds and the process tree was safely terminated.")]
    SubprocessTimeout,

    #[error("Skipped undoing '{0}' because the file was modified after being moved.")]
    UndoModifiedConflict(String),

    #[error("No undoable command found in history.")]
    NothingToUndo,

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

impl VoxError {
    pub fn error_code(&self) -> &'static str {
        match self {
            VoxError::SttSilence => "ERR_STT_SILENCE",
            VoxError::PathOutsideSandbox(_) => "ERR_PATH_OUTSIDE_SANDBOX",
            VoxError::PathTraversalDetected => "ERR_PATH_TRAVERSAL",
            VoxError::HiddenDotfileBlocked(_) => "ERR_HIDDEN_DOTFILE",
            VoxError::ExecutableGuard(_) => "ERR_EXECUTABLE_GUARD",
            VoxError::SourceNotFound(_) => "ERR_SOURCE_NOT_FOUND",
            VoxError::BatchLimitExceeded(_) => "ERR_BATCH_LIMIT_EXCEEDED",
            VoxError::FileLocked(_) => "ERR_FILE_LOCKED",
            VoxError::WingetAmbiguous(_) => "ERR_WINGET_AMBIGUOUS",
            VoxError::SubprocessTimeout => "ERR_SUBPROCESS_TIMEOUT",
            VoxError::UndoModifiedConflict(_) => "ERR_UNDO_MODIFIED",
            VoxError::NothingToUndo => "ERR_NOTHING_TO_UNDO",
            VoxError::Database(_) => "ERR_DATABASE_INTERNAL",
            VoxError::Io(_) => "ERR_IO_FAILURE",
        }
    }
}

// Required by Tauri v2 so Result<T, VoxError> can be returned directly from #[tauri::command]
impl Serialize for VoxError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let payload = ErrorResponse {
            code: self.error_code(),
            message: self.to_string(),
        };
        payload.serialize(serializer)
    }
}
