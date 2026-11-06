use crate::error::VoxError;
use crate::executors::dry_run::{FileActionType, ValidatedFileDryRunPlan};
use crate::executors::quarantine::{execute_quarantine_delete_batch, stage_overwrite_file};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_HASH_FILE_SIZE_BYTES: u64 = 52_428_800; // 50 MB (`FR-3 Step 1`)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpLogRecord {
    pub command_id: String,
    pub execution_order: i32,
    pub operation_type: String,
    pub source_path: String,
    pub destination_path: String,
    pub is_directory: bool,
    pub file_size_bytes: u64,
    pub pre_op_mtime_ms: i64,
    pub post_op_mtime_ms: Option<i64>,
    pub file_hash_sha256: Option<String>,
    pub op_status: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchExecutionReceipt {
    pub command_id: String,
    pub final_status: String, // COMPLETED | PARTIALLY_COMPLETED | FAILED
    pub succeeded_count: usize,
    pub failed_count: usize,
    pub errors: Vec<String>,
}

/// SRS-02: Unified atomic move helper with automatic cross-device (C: <-> D: or /home <-> /mnt)
/// copy + SHA-256 verification + delete fallback.
pub fn atomic_move_file(src: &Path, dst: &Path) -> Result<(), VoxError> {
    if let Some(parent) = dst.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(err) if is_cross_device_error(&err) => {
            let src_meta = fs::metadata(src)?;
            let expected_len = src_meta.len();
            let expected_hash = compute_sha256_if_eligible(src, expected_len)?;

            fs::copy(src, dst)?;

            let dst_meta = fs::metadata(dst)?;
            if dst_meta.len() != expected_len {
                let _ = fs::remove_file(dst);
                return Err(VoxError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cross-drive copy size mismatch",
                )));
            }

            if let Some(ref src_sha) = expected_hash {
                let dst_sha = compute_sha256_if_eligible(dst, dst_meta.len())?;
                if dst_sha.as_ref() != Some(src_sha) {
                    let _ = fs::remove_file(dst);
                    return Err(VoxError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Cross-drive SHA-256 verification failed",
                    )));
                }
            }

            fs::remove_file(src)?;
            Ok(())
        }
        Err(err) => Err(VoxError::Io(err)),
    }
}

fn is_cross_device_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::CrossesDevices {
        return true;
    }
    matches!(err.raw_os_error(), Some(17) | Some(18))
}

/// Computes SHA-256 hex digest if the file is <= 50 MB (`FR-3`).
pub fn compute_sha256_if_eligible(
    path: &Path,
    file_size_bytes: u64,
) -> Result<Option<String>, VoxError> {
    if file_size_bytes > MAX_HASH_FILE_SIZE_BYTES || !path.is_file() {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();
    let hex_string: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(Some(hex_string))
}

pub fn get_mtime_ms(meta: &Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Inserts a `command_logs` parent row and executes a validated Dry-Run plan,
/// performing all filesystem I/O before committing the batch to SQLite (`SADD-03`).
pub fn execute_validated_file_plan(
    conn: &mut Connection,
    plan: &ValidatedFileDryRunPlan,
    skip_quarantine_on_delete: bool,
    custom_quarantine_root: Option<&Path>,
) -> Result<BatchExecutionReceipt, VoxError> {
    // Ensure parent command_logs row exists in 'EXECUTING' state
    conn.execute(
        "INSERT OR REPLACE INTO command_logs 
         (id, raw_transcript, action_type, parsed_intent_json, security_tier, requires_auth, auth_method, execution_status, is_undoable)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, 'UI_CLICK', 'EXECUTING', 1)",
        params![
            plan.command_id,
            plan.raw_transcript,
            plan.action_type.as_db_str(),
            serde_json::to_string(plan).unwrap_or_else(|_| "{}".to_string()),
            plan.security_tier.as_db_str(),
        ],
    )?;

    // Delegate FILE_DELETE to Stage-1 Quarantine engine
    if plan.action_type == FileActionType::FileDelete {
        let target_files: Vec<PathBuf> = plan
            .items
            .iter()
            .map(|i| i.source_path.clone())
            .collect();
        let records = execute_quarantine_delete_batch(
            conn,
            &plan.command_id,
            &target_files,
            skip_quarantine_on_delete,
            custom_quarantine_root,
        )?;
        return finalize_command_receipt(conn, &plan.command_id, &records);
    }

    let mut records: Vec<FileOpLogRecord> = Vec::new();
    let mut order_counter: i32 = 1;

    // Step 1: Create destination folder if needed (logged as MKDIR at execution_order = 1)
    if let Some(ref dir_to_create) = plan.create_dest_dir {
        if !dir_to_create.exists() {
            fs::create_dir_all(dir_to_create)?;
            let dir_meta = fs::metadata(dir_to_create)?;
            let mtime = get_mtime_ms(&dir_meta);

            records.push(FileOpLogRecord {
                command_id: plan.command_id.clone(),
                execution_order: order_counter,
                operation_type: "MKDIR".to_string(),
                source_path: dir_to_create.to_string_lossy().into_owned(),
                destination_path: dir_to_create.to_string_lossy().into_owned(),
                is_directory: true,
                file_size_bytes: 0,
                pre_op_mtime_ms: mtime,
                post_op_mtime_ms: Some(mtime),
                file_hash_sha256: None,
                op_status: "SUCCESS".to_string(),
                error_message: None,
            });
            order_counter += 1;
        }
    }

    if plan.action_type == FileActionType::DirCreate {
        insert_file_operations_batch(conn, &records)?;
        return finalize_command_receipt(conn, &plan.command_id, &records);
    }

    // Step 2: Execute FILE_MOVE, FILE_COPY, or FILE_RENAME items
    for item in &plan.items {
        // PRD-01: If overwriting an existing destination file, stage it into Quarantine first!
        if item.will_overwrite && item.destination_path.exists() {
            let staged_record = stage_overwrite_file(
                &item.destination_path,
                &plan.command_id,
                order_counter,
                custom_quarantine_root,
            )?;
            records.push(staged_record);
            order_counter += 1;
        }

        let src_meta = match fs::metadata(&item.source_path) {
            Ok(m) => m,
            Err(err) => {
                records.push(FileOpLogRecord {
                    command_id: plan.command_id.clone(),
                    execution_order: order_counter,
                    operation_type: map_op_type(plan.action_type).to_string(),
                    source_path: item.source_path.to_string_lossy().into_owned(),
                    destination_path: item.destination_path.to_string_lossy().into_owned(),
                    is_directory: false,
                    file_size_bytes: 0,
                    pre_op_mtime_ms: 0,
                    post_op_mtime_ms: None,
                    file_hash_sha256: None,
                    op_status: "FAILED".to_string(),
                    error_message: Some(err.to_string()),
                });
                order_counter += 1;
                continue;
            }
        };

        let file_size_bytes = src_meta.len();
        let pre_op_mtime_ms = get_mtime_ms(&src_meta);
        let file_hash_sha256 = compute_sha256_if_eligible(&item.source_path, file_size_bytes)?;

        let op_result = match plan.action_type {
            FileActionType::FileMove | FileActionType::FileRename => {
                atomic_move_file(&item.source_path, &item.destination_path)
            }
            FileActionType::FileCopy => {
                if let Some(p) = item.destination_path.parent() {
                    let _ = fs::create_dir_all(p);
                }
                fs::copy(&item.source_path, &item.destination_path)
                    .map(|_| ())
                    .map_err(VoxError::Io)
            }
            _ => Ok(()),
        };

        match op_result {
            Ok(()) => {
                let post_op_mtime_ms = fs::metadata(&item.destination_path)
                    .ok()
                    .map(|m| get_mtime_ms(&m));
                records.push(FileOpLogRecord {
                    command_id: plan.command_id.clone(),
                    execution_order: order_counter,
                    operation_type: map_op_type(plan.action_type).to_string(),
                    source_path: item.source_path.to_string_lossy().into_owned(),
                    destination_path: item.destination_path.to_string_lossy().into_owned(),
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
                    command_id: plan.command_id.clone(),
                    execution_order: order_counter,
                    operation_type: map_op_type(plan.action_type).to_string(),
                    source_path: item.source_path.to_string_lossy().into_owned(),
                    destination_path: item.destination_path.to_string_lossy().into_owned(),
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

        order_counter += 1;
    }

    insert_file_operations_batch(conn, &records)?;
    finalize_command_receipt(conn, &plan.command_id, &records)
}

fn map_op_type(action: FileActionType) -> &'static str {
    match action {
        FileActionType::FileMove => "MOVE",
        FileActionType::FileCopy => "COPY",
        FileActionType::FileRename => "RENAME",
        FileActionType::FileDelete => "SOFT_DELETE",
        FileActionType::DirCreate => "MKDIR",
    }
}

/// Batch-inserts all `FileOpLogRecord` entries inside a single fast SQLite transaction (`SADD-03`).
pub fn insert_file_operations_batch(
    conn: &mut Connection,
    records: &[FileOpLogRecord],
) -> Result<(), VoxError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO file_operations (
                command_id, execution_order, operation_type, source_path, destination_path,
                is_directory, file_size_bytes, pre_op_mtime_ms, post_op_mtime_ms,
                file_hash_sha256, op_status, error_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;

        for rec in records {
            stmt.execute(params![
                rec.command_id,
                rec.execution_order,
                rec.operation_type,
                rec.source_path,
                rec.destination_path,
                if rec.is_directory { 1 } else { 0 },
                rec.file_size_bytes as i64,
                rec.pre_op_mtime_ms,
                rec.post_op_mtime_ms,
                rec.file_hash_sha256,
                rec.op_status,
                rec.error_message,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn finalize_command_receipt(
    conn: &mut Connection,
    command_id: &str,
    records: &[FileOpLogRecord],
) -> Result<BatchExecutionReceipt, VoxError> {
    let mut succeeded_count = 0usize;
    let mut failed_count = 0usize;
    let mut errors = Vec::new();

    for rec in records {
        if rec.op_status == "SUCCESS" || rec.op_status == "FLUSHED_TO_TRASH" {
            succeeded_count += 1;
        } else {
            failed_count += 1;
            if let Some(ref e) = rec.error_message {
                errors.push(e.clone());
            }
        }
    }

    let final_status = if failed_count == 0 {
        "COMPLETED"
    } else if succeeded_count > 0 {
        "PARTIALLY_COMPLETED"
    } else {
        "FAILED"
    };

    let is_undoable = if succeeded_count > 0 { 1 } else { 0 };

    conn.execute(
        "UPDATE command_logs 
         SET execution_status = ?1, is_undoable = ?2, exit_code = ?3
         WHERE id = ?4",
        params![
            final_status,
            is_undoable,
            if failed_count == 0 { 0 } else { 1 },
            command_id
        ],
    )?;

    Ok(BatchExecutionReceipt {
        command_id: command_id.to_string(),
        final_status: final_status.to_string(),
        succeeded_count,
        failed_count,
        errors,
    })
}
