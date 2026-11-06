use crate::error::VoxError;
use rusqlite::{params, Connection};
use std::path::PathBuf;

/// Seeds the standard user directories (ALLOW) and protected subdirectories (BLOCK)
/// into the `sandbox_rules` table on application boot.
pub fn seed_default_sandbox_rules(conn: &Connection) -> Result<(), VoxError> {
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
    let mut block_dirs: Vec<(PathBuf, &str, &str)> = Vec::new();

    if let Some(docs) = dirs::document_dir() {
        let canonical_docs = dunce::canonicalize(&docs).unwrap_or(docs);
        block_dirs.push((
            canonical_docs.join("PowerShell"),
            "WINDOWS",
            "Block PowerShell Profile Directory",
        ));
        block_dirs.push((
            canonical_docs.join("WindowsPowerShell"),
            "WINDOWS",
            "Block WindowsPowerShell Profile Directory",
        ));
    }

    if let Some(data_local) = dirs::data_local_dir() {
        let canonical_local = dunce::canonicalize(&data_local).unwrap_or(data_local);
        block_dirs.push((
            canonical_local.join("VoxShell"),
            "ALL",
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
            "WINDOWS",
            "Block Windows Startup Folder",
        ));
    }

    if let Some(config_dir) = dirs::config_dir() {
        let canonical_config = dunce::canonicalize(&config_dir).unwrap_or(config_dir);
        block_dirs.push((
            canonical_config.join("autostart"),
            "LINUX",
            "Block Linux XDG Autostart Directory",
        ));
    }

    for (path, os_target, desc) in block_dirs {
        conn.execute(
            "INSERT OR IGNORE INTO sandbox_rules 
             (path_pattern, match_type, rule_type, os_target, is_system_default, description)
             VALUES (?1, 'PREFIX_DIR', 'BLOCK', ?2, 1, ?3)",
            params![path.to_string_lossy().as_ref(), os_target, desc],
        )?;
    }

    Ok(())
}
