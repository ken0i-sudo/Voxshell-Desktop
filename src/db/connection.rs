use crate::error::VoxError;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

const INIT_SCHEMA_SQL: &str = include_str!("../../migrations/001_init_v2_schema.sql");

/// Opens (or creates) the VoxShell SQLite database in WAL mode, runs migrations,
/// performs NFR-4 crash recovery, and seeds default OS sandbox rules.
pub fn init_database(db_path: &Path) -> Result<Connection, VoxError> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(db_path)?;

    // Enforce WAL concurrency mode, foreign keys, and busy timeout
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;

    // Run schema migration
    conn.execute_batch(INIT_SCHEMA_SQL)?;

    // NFR-4: Recover any commands stuck in 'EXECUTING' from an unexpected OS/app crash
    recover_interrupted_commands(&conn)?;

    // Seed default ALLOW and BLOCK directories for the current OS user
    seed_default_sandbox_rules(&conn)?;

    Ok(conn)
}

/// NFR-4: Marks any row stuck in 'EXECUTING' as 'FAILED' on startup.
fn recover_interrupted_commands(conn: &Connection) -> Result<usize, VoxError> {
    let recovered = conn.execute(
        "UPDATE command_logs 
         SET execution_status = 'FAILED', 
             stderr_log = COALESCE(stderr_log, '') || '\n[NFR-4 Recovery] Interrupted by unexpected shutdown.'
         WHERE execution_status = 'EXECUTING'",
        [],
    )?;
    Ok(recovered)
}

/// Seeds the standard user directories (ALLOW) and protected subdirectories (BLOCK).
fn seed_default_sandbox_rules(conn: &Connection) -> Result<(), VoxError> {
    let allow_dirs: Vec<Option<(PathBuf, &str)>> = vec![
        dirs::download_dir().map(|p| (p, "User Downloads Directory")),
        dirs::document_dir().map(|p| (p, "User Documents Directory")),
        dirs::desktop_dir().map(|p| (p, "User Desktop Directory")),
        dirs::picture_dir().map(|p| (p, "User Pictures Directory")),
        dirs::audio_dir().map(|p| (p, "User Music Directory")),
        dirs::video_dir().map(|p| (p, "User Videos Directory")),
    ];

    for entry in allow_dirs.into_iter().flatten() {
        let (path, desc) = entry;
        let canonical = dunce::canonicalize(&path).unwrap_or(path);
        conn.execute(
            "INSERT OR IGNORE INTO sandbox_rules 
             (path_pattern, match_type, rule_type, os_target, is_system_default, description)
             VALUES (?1, 'PREFIX_DIR', 'ALLOW', 'ALL', 1, ?2)",
            params![canonical.to_string_lossy().as_ref(), desc],
        )?;
    }

    // Seed hard-blocked subdirectories inside user folders (FR-1 Step 5)
    let mut block_dirs: Vec<(PathBuf, &str)> = Vec::new();

    if let Some(docs) = dirs::document_dir() {
        let canonical_docs = dunce::canonicalize(&docs).unwrap_or(docs);
        block_dirs.push((
            canonical_docs.join("PowerShell"),
            "Block PowerShell Profile Directory",
        ));
        block_dirs.push((
            canonical_docs.join("WindowsPowerShell"),
            "Block WindowsPowerShell Profile Directory",
        ));
    }

    if let Some(data_local) = dirs::data_local_dir() {
        let canonical_local = dunce::canonicalize(&data_local).unwrap_or(data_local);
        block_dirs.push((
            canonical_local.join("VoxShell"),
            "Block VoxShell Internal Database & Quarantine Folder",
        ));
    }

    if let Some(data_roaming) = dirs::data_dir() {
        let canonical_roaming = dunce::canonicalize(&data_roaming).unwrap_or(data_roaming);
        block_dirs.push((
            canonical_roaming
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
            "Block Windows Startup Folder",
        ));
    }

    for (path, desc) in block_dirs {
        conn.execute(
            "INSERT OR IGNORE INTO sandbox_rules 
             (path_pattern, match_type, rule_type, os_target, is_system_default, description)
             VALUES (?1, 'PREFIX_DIR', 'BLOCK', 'ALL', 1, ?2)",
            params![path.to_string_lossy().as_ref(), desc],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_v2_init_and_crash_recovery() {
        let temp_db = std::env::temp_dir().join(format!("voxshell_test_{}.db", uuid::Uuid::new_v4()));
        let conn = init_database(&temp_db).expect("Failed to initialize SQLite v2.1 DB");

        // Verify default user_settings were seeded
        let hotkey: String = conn
            .query_row(
                "SELECT setting_value FROM user_settings WHERE setting_key = 'global_hotkey'",
                [],
                |row| row.get(0),
            )
            .expect("global_hotkey should be seeded");
        assert_eq!(hotkey, "Alt+Space");

        // Insert a simulated stuck 'EXECUTING' command and verify NFR-4 recovery marks it 'FAILED'
        conn.execute(
            "INSERT INTO command_logs (id, raw_transcript, action_type, parsed_intent_json, security_tier, execution_status)
             VALUES ('cmd_stuck_1', 'Install Discord', 'APP_INSTALL', '{}', 'YELLOW', 'EXECUTING')",
            [],
        )
        .unwrap();

        let recovered_count = recover_interrupted_commands(&conn).unwrap();
        assert_eq!(recovered_count, 1);

        let status: String = conn
            .query_row(
                "SELECT execution_status FROM command_logs WHERE id = 'cmd_stuck_1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "FAILED");

        let _ = std::fs::remove_file(&temp_db);
    }
}
