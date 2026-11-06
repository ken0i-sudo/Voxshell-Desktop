PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- 1. COMMAND_LOGS: Master audit log of every voice interaction & AI intent
CREATE TABLE IF NOT EXISTS command_logs (
    id TEXT PRIMARY KEY,
    raw_transcript TEXT NOT NULL,
    action_type TEXT NOT NULL
        CHECK (action_type IN (
            'APP_INSTALL', 'APP_UNINSTALL', 'APP_UPGRADE', 'APP_SEARCH', 'APP_LIST',
            'FILE_MOVE', 'FILE_COPY', 'FILE_RENAME', 'FILE_DELETE', 'DIR_CREATE',
            'SYSTEM_UNDO'
        )),
    parsed_intent_json TEXT NOT NULL CHECK (json_valid(parsed_intent_json)),
    security_tier TEXT NOT NULL CHECK (security_tier IN ('GREEN', 'YELLOW', 'RED')),
    requires_auth INTEGER NOT NULL DEFAULT 0 CHECK (requires_auth IN (0, 1)),
    auth_method TEXT CHECK (auth_method IN ('AUTO', 'UI_CLICK', 'VOICE_CONFIRM', 'OS_BIOMETRIC', 'DENIED')),
    authorized_at_ms INTEGER,
    execution_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (execution_status IN (
            'PENDING', 'DRY_RUN', 'EXECUTING', 
            'COMPLETED', 'PARTIALLY_COMPLETED', 
            'FAILED', 'CANCELLED', 
            'UNDONE', 'PARTIALLY_UNDONE'
        )),
    exit_code INTEGER,
    stdout_log TEXT,
    stderr_log TEXT,
    is_undoable INTEGER NOT NULL DEFAULT 0 CHECK (is_undoable IN (0, 1)),
    undone_at_ms INTEGER,
    undo_parent_id TEXT,
    created_at_ms INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)),
    FOREIGN KEY (undo_parent_id) REFERENCES command_logs(id) ON DELETE SET NULL
);

-- 2. FILE_OPERATIONS: Atomic file changes for deterministic Undo/Rollback
CREATE TABLE IF NOT EXISTS file_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id TEXT NOT NULL,
    execution_order INTEGER NOT NULL,
    operation_type TEXT NOT NULL
        CHECK (operation_type IN (
            'MOVE', 'COPY', 'RENAME', 'SOFT_DELETE', 
            'OVERWRITE_STAGING', 'FLUSH_TO_OS_TRASH', 'MKDIR'
        )),
    source_path TEXT NOT NULL,
    destination_path TEXT NOT NULL,
    is_directory INTEGER NOT NULL DEFAULT 0 CHECK (is_directory IN (0, 1)),
    file_size_bytes INTEGER NOT NULL DEFAULT 0,
    pre_op_mtime_ms INTEGER NOT NULL,
    post_op_mtime_ms INTEGER,
    file_hash_sha256 TEXT,
    op_status TEXT NOT NULL DEFAULT 'SUCCESS'
        CHECK (op_status IN ('SUCCESS', 'FAILED', 'UNDONE', 'UNDO_FAILED', 'FLUSHED_TO_TRASH')),
    error_message TEXT,
    executed_at_ms INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)),
    undone_at_ms INTEGER,
    FOREIGN KEY (command_id) REFERENCES command_logs(id) ON DELETE CASCADE
);

-- 3. PACKAGE_OPERATIONS: Tracks winget / pacman / apt lifecycle changes
CREATE TABLE IF NOT EXISTS package_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id TEXT NOT NULL,
    package_manager TEXT NOT NULL CHECK (package_manager IN ('WINGET', 'APT', 'PACMAN', 'FLATPAK')),
    operation_type TEXT NOT NULL CHECK (operation_type IN ('INSTALL', 'UNINSTALL', 'UPGRADE')),
    package_id TEXT NOT NULL,
    package_source TEXT NOT NULL DEFAULT 'winget',
    previous_version TEXT,
    target_version TEXT,
    argv_json TEXT NOT NULL CHECK (json_valid(argv_json)),
    op_status TEXT NOT NULL DEFAULT 'SUCCESS'
        CHECK (op_status IN ('SUCCESS', 'FAILED', 'UNDONE', 'UNDO_FAILED')),
    executed_at_ms INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)),
    undone_at_ms INTEGER,
    FOREIGN KEY (command_id) REFERENCES command_logs(id) ON DELETE CASCADE
);

-- 4. SANDBOX_RULES: Path allowlist & blocklist enforced by Rust backend
CREATE TABLE IF NOT EXISTS sandbox_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path_pattern TEXT NOT NULL,
    match_type TEXT NOT NULL DEFAULT 'PREFIX_DIR'
        CHECK (match_type IN ('PREFIX_DIR', 'EXACT_PATH', 'EXTENSION_BLOCK')),
    rule_type TEXT NOT NULL CHECK (rule_type IN ('ALLOW', 'BLOCK')),
    os_target TEXT NOT NULL DEFAULT 'ALL' CHECK (os_target IN ('ALL', 'WINDOWS', 'LINUX')),
    is_system_default INTEGER NOT NULL DEFAULT 1 CHECK (is_system_default IN (0, 1)),
    description TEXT,
    created_at_ms INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)),
    UNIQUE(path_pattern, os_target)
);

-- 5. USER_SETTINGS: Persistent app & UX configuration
CREATE TABLE IF NOT EXISTS user_settings (
    setting_key TEXT PRIMARY KEY
        CHECK (setting_key IN (
            'global_hotkey',
            'voice_capture_mode',
            'voice_confirm_enabled',
            'ai_onboarding_mode',
            'active_stt_provider',
            'active_llm_provider',
            'selected_microphone_id',
            'quarantine_max_bytes',
            'collision_default_policy'
        )),
    setting_value TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER))
);

INSERT OR IGNORE INTO user_settings (setting_key, setting_value) VALUES
    ('global_hotkey', 'Alt+Space'),
    ('voice_capture_mode', 'VAD_AUTO_STOP'),
    ('voice_confirm_enabled', 'true'),
    ('ai_onboarding_mode', 'ZERO_CONFIG'),
    ('active_stt_provider', 'LOCAL_WHISPER'),
    ('active_llm_provider', 'MANAGED_PROXY'),
    ('selected_microphone_id', 'DEFAULT'),
    ('quarantine_max_bytes', '5368709120'),
    ('collision_default_policy', 'AUTO_RENAME');

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cmd_logs_created ON command_logs(created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cmd_logs_undoable 
    ON command_logs(is_undoable, execution_status, created_at_ms DESC)
    WHERE is_undoable = 1 AND execution_status IN ('COMPLETED', 'PARTIALLY_COMPLETED');
CREATE INDEX IF NOT EXISTS idx_file_ops_rollback ON file_operations(command_id, execution_order DESC);
CREATE INDEX IF NOT EXISTS idx_file_ops_quarantine 
    ON file_operations(operation_type, op_status, executed_at_ms)
    WHERE operation_type IN ('SOFT_DELETE', 'OVERWRITE_STAGING') AND op_status = 'SUCCESS';
CREATE INDEX IF NOT EXISTS idx_pkg_ops_cmd ON package_operations(command_id);
