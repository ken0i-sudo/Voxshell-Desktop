use crate::error::VoxError;
use crate::executors::file_ops::{
    atomic_move_file, compute_sha256_if_eligible, get_mtime_ms, insert_file_operations_batch,
    now_epoch_ms, FileOpLogRecord,
};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_QUARANTINE_RETENTION_MS: i64 = 86_400_000; // 24 hours

/// Resolves the per-volume quarantine folder for a given source file and command_id (`PRD-02`).
pub fn resolve_quarantine_dir_for_file(
    source_file: &Path,
    command_id: &str,
    custom_quarantine_root: Option<&Path>,
) -> Result<PathBuf, VoxError> {
    if let Some(custom_root) = custom_quarantine_root {
        let dir = custom_root.join(command_id);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    let primary_local = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("VoxShell")
        .join("quarantine");

    // Check if source_file is on the same Windows drive prefix as primary_local
    let src_prefix = extract_volume_prefix(source_file);
    let local_prefix = extract_volume_prefix(&primary_local);

    let base_quarantine = if src_prefix.is_some() && src_prefix != local_prefix {
        // Secondary volume on Windows (e.g. D:\.voxshell_quarantine\)
        let vol_root = PathBuf::from(format!("{}\\", src_prefix.unwrap()));
        vol_root.join(".voxshell_quarantine")
    } else {
        primary_local
    };

    let cmd_dir = base_quarantine.join(command_id);
    fs::create_dir_all(&cmd_dir)?;
    Ok(cmd_dir)
}

fn extract_volume_prefix(path: &Path) -> Option<String> {
    path.components().find_map(|c| match c {
        Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().to_lowercase()),
        _ => None,
    })
}

/// Stages a single existing destination file into Quarantine before an authenticated overwrite (`PRD-01`).
pub fn stage_overwrite_file(
    target_to_replace: &Path,
    command_id: &str,
    execution_order: i32,
    custom_quarantine_root: Option<&Path>,
) -> Result<FileOpLogRecord, VoxError> {
    let quarantine_dir =
        resolve_quarantine_dir_for_file(target_to_replace, command_id, custom_quarantine_root)?;
    let orig_name = target_to_replace
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("overwritten_file");
    let quarantine_dest =
        quarantine_dir.join(format!("{}_overwrite_{}", execution_order, orig_name));

    let meta = fs::metadata(target_to_replace)?;
    let file_size_bytes = meta.len();
    let pre_op_mtime_ms = get_mtime_ms(&meta);
    let file_hash_sha256 = compute_sha256_if_eligible(target_to_replace, file_size_bytes)?;

    atomic_move_file(target_to_replace, &quarantine_dest)?;
    let post_meta = fs::metadata(&quarantine_dest)?;
    let post_op_mtime_ms = Some(get_mtime_ms(&post_meta));

    Ok(FileOpLogRecord {
        command_id: command_id.to_string(),
        execution_order,
        operation_type: "OVERWRITE_STAGING".to_string(),
        source_path: target_to_replace.to_string_lossy().into_owned(),
        destination_path: quarantine_dest.to_string_lossy().into_owned(),
        is_directory: false,
        file_size_bytes,
        pre_op_mtime_ms,
        post_op_mtime_ms,
        file_hash_sha256,
        op_status: "SUCCESS".to_string(),
        error_message: None,
    })
}

/// Executes Stage-1 Soft Delete (or direct OS Trash bypass if `skip_quarantine` is true).
pub fn execute_quarantine_delete_batch(
    conn: &mut Connection,
    command_id: &str,
    files: &[PathBuf],
    skip_quarantine: bool,
    custom_quarantine_root: Option<&Path>,
) -> Result<Vec<FileOpLogRecord>, VoxError> {
    let mut records = Vec::with_capacity(files.len());

    for (idx, file_path) in files.iter().enumerate() {
        let execution_order = (idx + 1) as i32;
        let meta = match fs::metadata(file_path) {
            Ok(m) => m,
            Err(e) => {
                records.push(FileOpLogRecord {
                    command_id: command_id.to_string(),
                    execution_order,
                    operation_type: "SOFT_DELETE".to_string(),
                    source_path: file_path.to_string_lossy().into_owned(),
                    destination_path: String::new(),
                    is_directory: false,
                    file_size_bytes: 0,
                    pre_op_mtime_ms: 0,
                    post_op_mtime_ms: None,
                    file_hash_sha256: None,
                    op_status: "FAILED".to_string(),
                    error_message: Some(e.to_string()),
                });
                continue;
            }
        };

        let file_size_bytes = meta.len();
        let pre_op_mtime_ms = get_mtime_ms(&meta);
        let file_hash_sha256 = compute_sha256_if_eligible(file_path, file_size_bytes)?;

        if skip_quarantine {
            // Direct flush to OS Recycle Bin / Linux Trash (PRD-02 > 2 GB checkbox)
            match trash::delete(file_path) {
                Ok(_) => records.push(FileOpLogRecord {
                    command_id: command_id.to_string(),
                    execution_order,
                    operation_type: "FLUSH_TO_OS_TRASH".to_string(),
                    source_path: file_path.to_string_lossy().into_owned(),
                    destination_path: "OS_RECYCLE_BIN".to_string(),
                    is_directory: false,
                    file_size_bytes,
                    pre_op_mtime_ms,
                    post_op_mtime_ms: None,
                    file_hash_sha256,
                    op_status: "FLUSHED_TO_TRASH".to_string(),
                    error_message: None,
                }),
                Err(err) => records.push(FileOpLogRecord {
                    command_id: command_id.to_string(),
                    execution_order,
                    operation_type: "FLUSH_TO_OS_TRASH".to_string(),
                    source_path: file_path.to_string_lossy().into_owned(),
                    destination_path: "OS_RECYCLE_BIN".to_string(),
                    is_directory: false,
                    file_size_bytes,
                    pre_op_mtime_ms,
                    post_op_mtime_ms: None,
                    file_hash_sha256,
                    op_status: "FAILED".to_string(),
                    error_message: Some(err.to_string()),
                }),
            }
        } else {
            let quarantine_dir =
                resolve_quarantine_dir_for_file(file_path, command_id, custom_quarantine_root)?;
            let orig_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("deleted_file");
            let quarantine_dest = quarantine_dir.join(format!("{}_{}", execution_order, orig_name));

            match atomic_move_file(file_path, &quarantine_dest) {
                Ok(_) => {
                    let post_op_mtime_ms = fs::metadata(&quarantine_dest)
                        .ok()
                        .map(|m| get_mtime_ms(&m));
                    records.push(FileOpLogRecord {
                        command_id: command_id.to_string(),
                        execution_order,
                        operation_type: "SOFT_DELETE".to_string(),
                        source_path: file_path.to_string_lossy().into_owned(),
                        destination_path: quarantine_dest.to_string_lossy().into_owned(),
                        is_directory: false,
                        file_size_bytes,
                        pre_op_mtime_ms,
                        post_op_mtime_ms,
                        file_hash_sha256,
                        op_status: "SUCCESS".to_string(),
                        error_message: None,
                    });
                }
                Err(err) => {
                    records.push(FileOpLogRecord {
                        command_id: command_id.to_string(),
                        execution_order,
                        operation_type: "SOFT_DELETE".to_string(),
                        source_path: file_path.to_string_lossy().into_owned(),
                        destination_path: quarantine_dest.to_string_lossy().into_owned(),
                        is_directory: false,
                        file_size_bytes,
                        pre_op_mtime_ms,
                        post_op_mtime_ms: None,
                        file_hash_sha256,
                        op_status: "FAILED".to_string(),
                        error_message: Some(err.to_string()),
                    });
                }
            }
        }
    }

    insert_file_operations_batch(conn, &records)?;
    Ok(records)
}

/// Stage-2 Background Worker (`FR-3 Step 2`): Flushes quarantined files older than `retention_ms`
/// into the native OS Recycle Bin / Linux Trash via the `trash` crate.
pub fn flush_expired_quarantine_files(
    conn: &mut Connection,
    retention_ms: i64,
) -> Result<usize, VoxError> {
    let cutoff_ms = now_epoch_ms() - retention_ms;

    let expired_rows: Vec<(i64, String)> = {
        let mut stmt = conn.prepare(
            "SELECT id, destination_path 
             FROM file_operations 
             WHERE operation_type IN ('SOFT_DELETE', 'OVERWRITE_STAGING') 
               AND op_status = 'SUCCESS' 
               AND executed_at_ms <= ?1",
        )?;
        let mapped = stmt.query_map(params![cutoff_ms], |row| Ok((row.get(0)?, row.get(1)?)))?;
        mapped.collect::<Result<Vec<_>, _>>()?
    };

    let mut flushed_count = 0usize;
    for (op_id, dest_str) in expired_rows {
        let dest_path = Path::new(&dest_str);
        if dest_path.exists() {
            if trash::delete(dest_path).is_ok() {
                conn.execute(
                    "UPDATE file_operations SET op_status = 'FLUSHED_TO_TRASH' WHERE id = ?1",
                    params![op_id],
                )?;
                flushed_count += 1;
            }
        } else {
            conn.execute(
                "UPDATE file_operations SET op_status = 'FLUSHED_TO_TRASH' WHERE id = ?1",
                params![op_id],
            )?;
        }
    }

    Ok(flushed_count)
}
