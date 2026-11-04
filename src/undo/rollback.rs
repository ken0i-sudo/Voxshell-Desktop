use crate::error::VoxError;
use crate::executors::file_ops::{
    atomic_move_file, compute_sha256_if_eligible, get_mtime_ms, now_epoch_ms,
};
use crate::executors::quarantine::resolve_quarantine_dir_for_file;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoReceipt {
    pub command_id: String,
    pub command_status: String, // UNDONE | PARTIALLY_UNDONE
    pub restored_count: usize,
    pub skipped_conflicts: Vec<String>,
}

struct StoredFileOp {
    id: i64,
    execution_order: i32,
    operation_type: String,
    source_path: String,
    destination_path: String,
    post_op_mtime_ms: Option<i64>,
    file_hash_sha256: Option<String>,
}

/// Rolls back a specific `command_id` (or the most recent undoable command if `None`)
/// in strict reverse execution order (`ORDER BY execution_order DESC`).
pub fn undo_command(
    conn: &mut Connection,
    target_command_id: Option<&str>,
    custom_quarantine_root: Option<&Path>,
) -> Result<UndoReceipt, VoxError> {
    let command_id: String = match target_command_id {
        Some(id) => id.to_string(),
        None => conn
            .query_row(
                "SELECT id FROM command_logs 
                 WHERE is_undoable = 1 
                   AND execution_status IN ('COMPLETED', 'PARTIALLY_COMPLETED')
                 ORDER BY created_at_ms DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| VoxError::NothingToUndo)?,
    };

    let ops: Vec<StoredFileOp> = {
        let mut stmt = conn.prepare(
            "SELECT id, execution_order, operation_type, source_path, destination_path, 
                    post_op_mtime_ms, file_hash_sha256
             FROM file_operations
             WHERE command_id = ?1 AND op_status = 'SUCCESS'
             ORDER BY execution_order DESC",
        )?;

        let mapped = stmt.query_map(params![command_id], |row| {
            Ok(StoredFileOp {
                id: row.get(0)?,
                execution_order: row.get(1)?,
                operation_type: row.get(2)?,
                source_path: row.get(3)?,
                destination_path: row.get(4)?,
                post_op_mtime_ms: row.get(5)?,
                file_hash_sha256: row.get(6)?,
            })
        })?;
        mapped.collect::<Result<Vec<_>, _>>()?
    };

    if ops.is_empty() {
        return Err(VoxError::NothingToUndo);
    }

    let mut restored_count = 0usize;
    let mut skipped_conflicts = Vec::new();
    let undone_ts = now_epoch_ms();

    for op in ops {
        let src_path = Path::new(&op.source_path);
        let dst_path = Path::new(&op.destination_path);

        match op.operation_type.as_str() {
            "MOVE" | "RENAME" => {
                if !dst_path.exists() {
                    mark_op_undo_failed(conn, op.id, "Destination file no longer exists")?;
                    skipped_conflicts.push(op.destination_path.clone());
                    continue;
                }

                // FR-4 Guard: Check if the file was modified by the user after being moved
                if was_file_modified_since_op(
                    dst_path,
                    op.post_op_mtime_ms,
                    op.file_hash_sha256.as_deref(),
                )? {
                    mark_op_undo_failed(
                        conn,
                        op.id,
                        VoxError::UndoModifiedConflict(op.destination_path.clone()).error_code(),
                    )?;
                    skipped_conflicts.push(op.destination_path.clone());
                    continue;
                }

                if src_path.exists() {
                    mark_op_undo_failed(conn, op.id, "Original source path is now occupied")?;
                    skipped_conflicts.push(op.source_path.clone());
                    continue;
                }

                atomic_move_file(dst_path, src_path)?;
                mark_op_undone(conn, op.id, undone_ts)?;
                restored_count += 1;
            }

            "SOFT_DELETE" | "OVERWRITE_STAGING" => {
                if !dst_path.exists() {
                    mark_op_undo_failed(conn, op.id, "Quarantined file missing")?;
                    skipped_conflicts.push(op.source_path.clone());
                    continue;
                }

                if src_path.exists() {
                    mark_op_undo_failed(
                        conn,
                        op.id,
                        "Cannot restore quarantined file because original path is occupied",
                    )?;
                    skipped_conflicts.push(op.source_path.clone());
                    continue;
                }

                atomic_move_file(dst_path, src_path)?;
                mark_op_undone(conn, op.id, undone_ts)?;
                restored_count += 1;
            }

            "COPY" => {
                if !dst_path.exists() {
                    mark_op_undone(conn, op.id, undone_ts)?;
                    continue;
                }

                if was_file_modified_since_op(
                    dst_path,
                    op.post_op_mtime_ms,
                    op.file_hash_sha256.as_deref(),
                )? {
                    mark_op_undo_failed(
                        conn,
                        op.id,
                        VoxError::UndoModifiedConflict(op.destination_path.clone()).error_code(),
                    )?;
                    skipped_conflicts.push(op.destination_path.clone());
                    continue;
                }

                // FR-4: Move copied file to quarantine rather than hard-deleting it
                let q_dir = resolve_quarantine_dir_for_file(
                    dst_path,
                    &command_id,
                    custom_quarantine_root,
                )?;
                let fname = dst_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("copied_file");
                let q_dest = q_dir.join(format!("undo_copy_{}_{}", op.execution_order, fname));
                atomic_move_file(dst_path, &q_dest)?;
                mark_op_undone(conn, op.id, undone_ts)?;
                restored_count += 1;
            }

            "MKDIR" => {
                if dst_path.exists() && dst_path.is_dir() {
                    let is_empty = fs::read_dir(dst_path)?.next().is_none();
                    if is_empty {
                        fs::remove_dir(dst_path)?;
                        mark_op_undone(conn, op.id, undone_ts)?;
                        restored_count += 1;
                    } else {
                        mark_op_undo_failed(
                            conn,
                            op.id,
                            "Directory non-empty; preserved user files inside directory",
                        )?;
                    }
                } else {
                    mark_op_undone(conn, op.id, undone_ts)?;
                }
            }

            _ => {}
        }
    }

    let command_status = if skipped_conflicts.is_empty() {
        "UNDONE"
    } else {
        "PARTIALLY_UNDONE"
    };

    conn.execute(
        "UPDATE command_logs 
         SET execution_status = ?1, is_undoable = 0, undone_at_ms = ?2
         WHERE id = ?3",
        params![command_status, undone_ts, command_id],
    )?;

    Ok(UndoReceipt {
        command_id,
        command_status: command_status.to_string(),
        restored_count,
        skipped_conflicts,
    })
}

fn was_file_modified_since_op(
    path: &Path,
    recorded_mtime_ms: Option<i64>,
    recorded_sha256: Option<&str>,
) -> Result<bool, VoxError> {
    let meta = fs::metadata(path)?;
    let current_mtime = get_mtime_ms(&meta);

    if let Some(expected_sha) = recorded_sha256 {
        if let Some(current_sha) = compute_sha256_if_eligible(path, meta.len())? {
            return Ok(current_sha != expected_sha);
        }
    }

    if let Some(expected_mtime) = recorded_mtime_ms {
        return Ok(current_mtime != expected_mtime);
    }

    Ok(false)
}

fn mark_op_undone(conn: &Connection, op_id: i64, undone_ts: i64) -> Result<(), VoxError> {
    conn.execute(
        "UPDATE file_operations SET op_status = 'UNDONE', undone_at_ms = ?1 WHERE id = ?2",
        params![undone_ts, op_id],
    )?;
    Ok(())
}

fn mark_op_undo_failed(conn: &Connection, op_id: i64, reason: &str) -> Result<(), VoxError> {
    conn.execute(
        "UPDATE file_operations SET op_status = 'UNDO_FAILED', error_message = ?1 WHERE id = ?2",
        params![reason, op_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::connection::init_database;
    use crate::executors::dry_run::{
        build_file_dry_run_with_bases, CollisionPolicy, FileActionType, FileIntentRequest,
    };
    use crate::executors::file_ops::execute_validated_file_plan;
    use crate::security::sandbox::{BaseDirEnum, PathSandbox};
    use std::path::PathBuf;

    fn setup_phase2_test_env() -> (PathBuf, Connection, PathSandbox, PathBuf, PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("voxshell_phase2_test_{}", uuid::Uuid::new_v4()));
        let downloads = root.join("Downloads");
        let documents = root.join("Documents");
        let quarantine = root.join("Quarantine");
        let db_path = root.join("voxshell_test.db");

        fs::create_dir_all(&downloads).unwrap();
        fs::create_dir_all(&documents).unwrap();
        fs::create_dir_all(&quarantine).unwrap();

        let conn = init_database(&db_path).unwrap();
        let canon_dl = dunce::canonicalize(&downloads).unwrap();
        let canon_docs = dunce::canonicalize(&documents).unwrap();

        let sandbox = PathSandbox::with_custom_rules(
            vec![
                PathSandbox::to_discrete_lowercase_blocks(&canon_dl),
                PathSandbox::to_discrete_lowercase_blocks(&canon_docs),
            ],
            vec![],
        );

        (root, conn, sandbox, canon_dl, canon_docs, quarantine)
    }

    #[test]
    fn test_batch_move_mkdir_and_reverse_order_undo() {
        let (root, mut conn, sandbox, downloads, documents, quarantine) = setup_phase2_test_env();

        // Create 2 PDF files and 1 TXT file in Downloads
        fs::write(downloads.join("a_invoice.pdf"), b"pdf_content_1").unwrap();
        fs::write(downloads.join("b_receipt.pdf"), b"pdf_content_2").unwrap();
        fs::write(downloads.join("ignore.txt"), b"txt_content").unwrap();

        let req = FileIntentRequest {
            command_id: "cmd_move_pdfs".to_string(),
            raw_transcript: "Move all PDFs from Downloads to Invoices in Documents".to_string(),
            action_type: FileActionType::FileMove,
            human_summary: "Move 2 PDFs to Documents/Invoices".to_string(),
            source_base_dir: Some(BaseDirEnum::Downloads),
            source_relative_path: None,
            file_filter_extensions: Some(vec!["pdf".to_string()]),
            file_name_contains: None,
            destination_base_dir: Some(BaseDirEnum::Documents),
            destination_relative_path: Some("Invoices".to_string()),
            create_destination_if_missing: true,
            recursive: false,
            collision_policy: CollisionPolicy::AutoRename,
        };

        let plan = build_file_dry_run_with_bases(&sandbox, &req, Some(&downloads), Some(&documents))
            .expect("Dry-run should succeed");
        assert_eq!(plan.items.len(), 2);

        let receipt = execute_validated_file_plan(&mut conn, &plan, false, Some(&quarantine))
            .expect("Execution should succeed");
        assert_eq!(receipt.final_status, "COMPLETED");
        assert!(documents.join("Invoices/a_invoice.pdf").exists());
        assert!(documents.join("Invoices/b_receipt.pdf").exists());
        assert!(!downloads.join("a_invoice.pdf").exists());

        // Now run reverse-order Undo: both PDFs should return to Downloads and empty 'Invoices' dir removed
        let undo_res =
            undo_command(&mut conn, Some("cmd_move_pdfs"), Some(&quarantine)).expect("Undo failed");
        assert_eq!(undo_res.command_status, "UNDONE");
        assert!(downloads.join("a_invoice.pdf").exists());
        assert!(downloads.join("b_receipt.pdf").exists());
        assert!(!documents.join("Invoices").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_modified_file_conflict_guard_skips_overwrite_on_undo() {
        let (root, mut conn, sandbox, downloads, documents, quarantine) = setup_phase2_test_env();

        fs::write(downloads.join("draft.pdf"), b"original_v1").unwrap();

        let req = FileIntentRequest {
            command_id: "cmd_edit_guard".to_string(),
            raw_transcript: "Move draft.pdf to Documents".to_string(),
            action_type: FileActionType::FileMove,
            human_summary: "Move draft.pdf".to_string(),
            source_base_dir: Some(BaseDirEnum::Downloads),
            source_relative_path: Some("draft.pdf".to_string()),
            file_filter_extensions: None,
            file_name_contains: None,
            destination_base_dir: Some(BaseDirEnum::Documents),
            destination_relative_path: None,
            create_destination_if_missing: false,
            recursive: false,
            collision_policy: CollisionPolicy::AutoRename,
        };

        let plan =
            build_file_dry_run_with_bases(&sandbox, &req, Some(&downloads), Some(&documents))
                .unwrap();
        execute_validated_file_plan(&mut conn, &plan, false, Some(&quarantine)).unwrap();

        // Simulate user editing 'Documents/draft.pdf' after moving it
        fs::write(documents.join("draft.pdf"), b"user_edited_v2_important_work").unwrap();

        // Undo must detect the SHA-256 mismatch and skip undoing 'draft.pdf' (PARTIALLY_UNDONE)
        let undo_res =
            undo_command(&mut conn, Some("cmd_edit_guard"), Some(&quarantine)).unwrap();
        assert_eq!(undo_res.command_status, "PARTIALLY_UNDONE");
        assert_eq!(undo_res.skipped_conflicts.len(), 1);
        assert_eq!(
            fs::read_to_string(documents.join("draft.pdf")).unwrap(),
            "user_edited_v2_important_work"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_quarantine_soft_delete_and_overwrite_staging_restore() {
        let (root, mut conn, sandbox, downloads, documents, quarantine) = setup_phase2_test_env();

        // 1. Test Quarantine Overwrite Staging (PRD-01):
        // Both Downloads/report.pdf and Documents/report.pdf exist with different contents.
        fs::write(downloads.join("report.pdf"), b"new_downloads_version").unwrap();
        fs::write(documents.join("report.pdf"), b"existing_documents_version").unwrap();

        let overwrite_req = FileIntentRequest {
            command_id: "cmd_overwrite_1".to_string(),
            raw_transcript: "Move report.pdf to Documents and overwrite".to_string(),
            action_type: FileActionType::FileMove,
            human_summary: "Overwrite report.pdf in Documents".to_string(),
            source_base_dir: Some(BaseDirEnum::Downloads),
            source_relative_path: Some("report.pdf".to_string()),
            file_filter_extensions: None,
            file_name_contains: None,
            destination_base_dir: Some(BaseDirEnum::Documents),
            destination_relative_path: None,
            create_destination_if_missing: false,
            recursive: false,
            collision_policy: CollisionPolicy::QuarantineOverwrite,
        };

        let plan = build_file_dry_run_with_bases(
            &sandbox,
            &overwrite_req,
            Some(&downloads),
            Some(&documents),
        )
        .unwrap();
        execute_validated_file_plan(&mut conn, &plan, false, Some(&quarantine)).unwrap();

        assert_eq!(
            fs::read_to_string(documents.join("report.pdf")).unwrap(),
            "new_downloads_version"
        );

        // Undoing the overwrite must restore BOTH files with zero data loss!
        let undo_overwrite =
            undo_command(&mut conn, Some("cmd_overwrite_1"), Some(&quarantine)).unwrap();
        assert_eq!(undo_overwrite.command_status, "UNDONE");
        assert_eq!(
            fs::read_to_string(downloads.join("report.pdf")).unwrap(),
            "new_downloads_version"
        );
        assert_eq!(
            fs::read_to_string(documents.join("report.pdf")).unwrap(),
            "existing_documents_version"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
