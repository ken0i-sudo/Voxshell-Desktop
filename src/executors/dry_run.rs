use crate::error::VoxError;
use crate::security::sandbox::{BaseDirEnum, PathSandbox};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_BATCH_FILES: usize = 500;
pub const LARGE_BATCH_WARNING_THRESHOLD: usize = 50;
pub const LARGE_DELETE_BYTES_THRESHOLD: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileActionType {
    FileMove,
    FileCopy,
    FileRename,
    FileDelete,
    DirCreate,
}

impl FileActionType {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            FileActionType::FileMove => "FILE_MOVE",
            FileActionType::FileCopy => "FILE_COPY",
            FileActionType::FileRename => "FILE_RENAME",
            FileActionType::FileDelete => "FILE_DELETE",
            FileActionType::DirCreate => "DIR_CREATE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollisionPolicy {
    AutoRename,
    QuarantineOverwrite,
}

impl Default for CollisionPolicy {
    fn default() -> Self {
        CollisionPolicy::AutoRename
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityTier {
    Green,
    Yellow,
    Red,
}

impl SecurityTier {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            SecurityTier::Green => "GREEN",
            SecurityTier::Yellow => "YELLOW",
            SecurityTier::Red => "RED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntentRequest {
    pub command_id: String,
    pub raw_transcript: String,
    pub action_type: FileActionType,
    pub human_summary: String,
    pub source_base_dir: Option<BaseDirEnum>,
    pub source_relative_path: Option<String>,
    pub file_filter_extensions: Option<Vec<String>>,
    pub file_name_contains: Option<String>,
    pub destination_base_dir: Option<BaseDirEnum>,
    pub destination_relative_path: Option<String>,
    pub create_destination_if_missing: bool,
    pub recursive: bool,
    pub collision_policy: CollisionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedFileItem {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub file_size_bytes: u64,
    pub will_overwrite: bool,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedFileDryRunPlan {
    pub command_id: String,
    pub raw_transcript: String,
    pub action_type: FileActionType,
    pub security_tier: SecurityTier,
    pub requires_auth: bool,
    pub human_summary: String,
    pub warnings: Vec<String>,
    pub collision_policy: CollisionPolicy,
    pub create_dest_dir: Option<PathBuf>,
    pub items: Vec<PlannedFileItem>,
    pub total_bytes_affected: u64,
}

/// Generates a non-destructive destination path like `report (1).pdf` if `dest` already exists.
pub fn compute_auto_rename_path(dest: &Path) -> PathBuf {
    if !dest.exists() {
        return dest.to_path_buf();
    }

    let parent = dest.parent().unwrap_or_else(|| Path::new(""));
    let stem = dest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = dest.extension().and_then(|e| e.to_str());

    for counter in 1..=9999 {
        let candidate_name = match ext {
            Some(e) => format!("{} ({}).{}", stem, counter, e),
            None => format!("{} ({})", stem, counter),
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }

    dest.to_path_buf()
}

/// Resolves and validates a FileIntentRequest using explicit base directories (for OS & unit tests).
pub fn build_file_dry_run_with_bases(
    sandbox: &PathSandbox,
    req: &FileIntentRequest,
    resolved_src_base: Option<&Path>,
    resolved_dst_base: Option<&Path>,
) -> Result<ValidatedFileDryRunPlan, VoxError> {
    let mut warnings = Vec::new();
    let mut items = Vec::new();
    let mut total_bytes_affected = 0u64;
    let mut security_tier = SecurityTier::Yellow;
    let mut create_dest_dir = None;

    // Case 1: DIR_CREATE
    if req.action_type == FileActionType::DirCreate {
        let dst_base = resolved_dst_base.ok_or_else(|| {
            VoxError::PathOutsideSandbox("Missing destination_base_dir".to_string())
        })?;
        let target_dir = sandbox.validate_with_base_path(
            dst_base,
            req.destination_relative_path.as_deref(),
            false,
        )?;

        items.push(PlannedFileItem {
            source_path: target_dir.clone(),
            destination_path: target_dir.clone(),
            file_size_bytes: 0,
            will_overwrite: false,
            is_directory: true,
        });

        return Ok(ValidatedFileDryRunPlan {
            command_id: req.command_id.clone(),
            raw_transcript: req.raw_transcript.clone(),
            action_type: req.action_type,
            security_tier,
            requires_auth: true,
            human_summary: req.human_summary.clone(),
            warnings,
            collision_policy: req.collision_policy,
            create_dest_dir: Some(target_dir),
            items,
            total_bytes_affected: 0,
        });
    }

    // Validate source path
    let src_base = resolved_src_base
        .ok_or_else(|| VoxError::PathOutsideSandbox("Missing source_base_dir".to_string()))?;
    let validated_src = sandbox.validate_with_base_path(
        src_base,
        req.source_relative_path.as_deref(),
        true,
    )?;

    // Collect matching source files
    let matched_files = collect_matching_files(
        sandbox,
        &validated_src,
        req.file_filter_extensions.as_deref(),
        req.file_name_contains.as_deref(),
        req.recursive,
    )?;

    if matched_files.is_empty() {
        return Err(VoxError::SourceNotFound(
            validated_src.to_string_lossy().into_owned(),
        ));
    }

    if matched_files.len() > MAX_BATCH_FILES {
        return Err(VoxError::BatchLimitExceeded(matched_files.len()));
    }

    // Case 2: FILE_DELETE (Always Red Tier)
    if req.action_type == FileActionType::FileDelete {
        security_tier = SecurityTier::Red;

        for file_path in matched_files {
            let meta = fs::metadata(&file_path)?;
            let size = meta.len();
            total_bytes_affected += size;

            if sandbox.is_high_risk_extension(&file_path) {
                warnings.push(format!(
                    "Executable/script file flagged for deletion: {}",
                    file_path.file_name().unwrap_or_default().to_string_lossy()
                ));
            }

            items.push(PlannedFileItem {
                source_path: file_path.clone(),
                destination_path: PathBuf::new(), // Populated during Stage-1 Quarantine
                file_size_bytes: size,
                will_overwrite: false,
                is_directory: false,
            });
        }

        if total_bytes_affected > LARGE_DELETE_BYTES_THRESHOLD {
            warnings.push(
                "Deletion exceeds 2 GB: You may optionally flush directly to the OS Recycle Bin."
                    .to_string(),
            );
        }
    } else {
        // Case 3: FILE_MOVE, FILE_COPY, or FILE_RENAME
        let dst_base = resolved_dst_base.ok_or_else(|| {
            VoxError::PathOutsideSandbox("Missing destination_base_dir".to_string())
        })?;
        let dst_base_enum = req.destination_base_dir.unwrap_or(BaseDirEnum::Documents);

        let validated_dst = sandbox.validate_with_base_path(
            dst_base,
            req.destination_relative_path.as_deref(),
            false,
        )?;

        let treat_dst_as_dir = req.action_type != FileActionType::FileRename
            && (validated_dst.is_dir()
                || matched_files.len() > 1
                || req.create_destination_if_missing);

        if treat_dst_as_dir && !validated_dst.exists() {
            create_dest_dir = Some(validated_dst.clone());
        }

        for file_path in matched_files {
            let meta = fs::metadata(&file_path)?;
            let size = meta.len();
            total_bytes_affected += size;

            let raw_target = if treat_dst_as_dir {
                let fname = file_path.file_name().ok_or_else(|| {
                    VoxError::SourceNotFound(file_path.to_string_lossy().into_owned())
                })?;
                validated_dst.join(fname)
            } else {
                validated_dst.clone()
            };

            // Enforce FR-1 Step 6 Executable Mutation Guard
            sandbox.check_executable_mutation_guard(&file_path, &raw_target, dst_base_enum)?;

            let mut will_overwrite = false;
            let final_target = if raw_target.exists() {
                match req.collision_policy {
                    CollisionPolicy::AutoRename => compute_auto_rename_path(&raw_target),
                    CollisionPolicy::QuarantineOverwrite => {
                        will_overwrite = true;
                        security_tier = SecurityTier::Red;
                        raw_target
                    }
                }
            } else {
                raw_target
            };

            items.push(PlannedFileItem {
                source_path: file_path,
                destination_path: final_target,
                file_size_bytes: size,
                will_overwrite,
                is_directory: false,
            });
        }
    }

    if items.len() > LARGE_BATCH_WARNING_THRESHOLD {
        security_tier = SecurityTier::Red;
        warnings.push(format!(
            "Large batch operation affecting {} files requires explicit confirmation.",
            items.len()
        ));
    }

    Ok(ValidatedFileDryRunPlan {
        command_id: req.command_id.clone(),
        raw_transcript: req.raw_transcript.clone(),
        action_type: req.action_type,
        security_tier,
        requires_auth: true,
        human_summary: req.human_summary.clone(),
        warnings,
        collision_policy: req.collision_policy,
        create_dest_dir,
        items,
        total_bytes_affected,
    })
}

fn collect_matching_files(
    sandbox: &PathSandbox,
    validated_src: &Path,
    filter_exts: Option<&[String]>,
    name_contains: Option<&str>,
    recursive: bool,
) -> Result<Vec<PathBuf>, VoxError> {
    if validated_src.is_file() {
        return Ok(vec![validated_src.to_path_buf()]);
    }

    let mut results = Vec::new();
    let normalized_exts: Option<Vec<String>> = filter_exts.map(|exts| {
        exts.iter()
            .map(|e| e.trim_start_matches('.').to_lowercase())
            .collect()
    });
    let lower_substr = name_contains.map(|s| s.to_lowercase());

    scan_dir_entries(
        sandbox,
        validated_src,
        normalized_exts.as_deref(),
        lower_substr.as_deref(),
        recursive,
        &mut results,
    )?;

    results.sort();
    Ok(results)
}

fn scan_dir_entries(
    sandbox: &PathSandbox,
    dir: &Path,
    exts: Option<&[String]>,
    substr: Option<&str>,
    recursive: bool,
    out: &mut Vec<PathBuf>,
) -> Result<(), VoxError> {
    for entry_res in fs::read_dir(dir)? {
        let entry = entry_res?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Always skip hidden dotfiles and dot-directories during directory scans
        if name_str.starts_with('.') {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            if recursive && sandbox.validate_with_base_path(&path, None, true).is_ok() {
                scan_dir_entries(sandbox, &path, exts, substr, recursive, out)?;
            }
            continue;
        }

        if file_type.is_file() {
            if let Some(allowed_exts) = exts {
                let file_ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_lowercase())
                    .unwrap_or_default();
                if !allowed_exts.contains(&file_ext) {
                    continue;
                }
            }

            if let Some(needle) = substr {
                if !name_str.to_lowercase().contains(needle) {
                    continue;
                }
            }

            out.push(path);
        }
    }
    Ok(())
}
