use crate::error::VoxError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Strict enum matching the LLM JSON Schema (`SRS Section 3.1`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BaseDirEnum {
    Downloads,
    Documents,
    Desktop,
    Pictures,
    Music,
    Videos,
}

impl BaseDirEnum {
    /// Resolves the enum to the real OS user directory path.
    pub fn resolve_os_dir(&self) -> Option<PathBuf> {
        match self {
            BaseDirEnum::Downloads => dirs::download_dir(),
            BaseDirEnum::Documents => dirs::document_dir(),
            BaseDirEnum::Desktop => dirs::desktop_dir(),
            BaseDirEnum::Pictures => dirs::picture_dir(),
            BaseDirEnum::Music => dirs::audio_dir(),
            BaseDirEnum::Videos => dirs::video_dir(),
        }
    }
}

/// High-risk extensions guarded by FR-1 Step 6.
const HIGH_RISK_EXTENSIONS: &[&str] = &[
    "exe", "msi", "ps1", "bat", "cmd", "vbs", "scr", "dll", "sh", "reg",
];

pub struct PathSandbox {
    allowed_block_rules: Vec<Vec<String>>,
    blocked_block_rules: Vec<Vec<String>>,
    high_risk_extensions: HashSet<&'static str>,
}

impl PathSandbox {
    /// Loads ALLOW and BLOCK directory rules from the SQLite `sandbox_rules` table.
    pub fn from_db(conn: &Connection) -> Result<Self, VoxError> {
        let mut stmt = conn.prepare(
            "SELECT path_pattern, rule_type FROM sandbox_rules WHERE match_type = 'PREFIX_DIR'",
        )?;

        let mut allowed_block_rules = Vec::new();
        let mut blocked_block_rules = Vec::new();

        let rows = stmt.query_map([], |row| {
            let pattern: String = row.get(0)?;
            let rule_type: String = row.get(1)?;
            Ok((pattern, rule_type))
        })?;

        for row in rows {
            let (pattern, rule_type) = row?;
            let blocks = Self::to_discrete_lowercase_blocks(Path::new(&pattern));
            if !blocks.is_empty() {
                if rule_type == "ALLOW" {
                    allowed_block_rules.push(blocks);
                } else if rule_type == "BLOCK" {
                    blocked_block_rules.push(blocks);
                }
            }
        }

        Ok(Self::with_custom_rules(
            allowed_block_rules,
            blocked_block_rules,
        ))
    }

    /// Constructs a `PathSandbox` directly from pre-split lowercase block vectors.
    pub fn with_custom_rules(
        allowed_block_rules: Vec<Vec<String>>,
        blocked_block_rules: Vec<Vec<String>>,
    ) -> Self {
        let high_risk_extensions = HIGH_RISK_EXTENSIONS.iter().copied().collect();
        Self {
            allowed_block_rules,
            blocked_block_rules,
            high_risk_extensions,
        }
    }

    /// Splits a path into discrete, lowercased folder/file component blocks (`SADD-01`).
    pub fn to_discrete_lowercase_blocks(path: &Path) -> Vec<String> {
        path.components()
            .filter_map(|c| match c {
                Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().to_lowercase()),
                Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
                _ => None,
            })
            .collect()
    }

    /// Compares discrete blocks sequentially as full items so partial folder names never collide.
    pub fn matches_block_prefix(candidate_blocks: &[String], rule_blocks: &[String]) -> bool {
        candidate_blocks.len() >= rule_blocks.len()
            && candidate_blocks[..rule_blocks.len()] == *rule_blocks
    }

    /// Validates a path using an explicit `base_dir` (used by `validate_path` and unit tests).
    pub fn validate_with_base_path(
        &self,
        base_dir: &Path,
        relative_untrusted: Option<&str>,
        must_exist: bool,
    ) -> Result<PathBuf, VoxError> {
        // Step 1: In-memory lexical cleaning (flatten '.' and reject '..' or hidden dotfiles)
        let mut clean_rel_blocks: Vec<OsString> = Vec::new();

        if let Some(rel_str) = relative_untrusted {
            let trimmed = rel_str.trim();
            if !trimmed.is_empty() {
                for comp in Path::new(trimmed).components() {
                    match comp {
                        Component::CurDir => continue,
                        Component::Normal(os_str) => {
                            let s = os_str.to_string_lossy();
                            if s.starts_with('.') {
                                return Err(VoxError::HiddenDotfileBlocked(s.into_owned()));
                            }
                            clean_rel_blocks.push(os_str.to_os_string());
                        }
                        _ => return Err(VoxError::PathTraversalDetected),
                    }
                }
            }
        }

        // Step 2: Disk canonicalization via `dunce` (resolving symlinks on existing ancestors)
        let candidate = clean_rel_blocks
            .iter()
            .fold(base_dir.to_path_buf(), |acc, p| acc.join(p));

        let resolved = if must_exist {
            dunce::canonicalize(&candidate).map_err(|_| {
                VoxError::SourceNotFound(candidate.to_string_lossy().into_owned())
            })?
        } else {
            self.canonicalize_non_existent(base_dir, &clean_rel_blocks)?
        };

        // Ensure the final resolved target did not resolve via a symlink to a hidden dotfile
        if let Some(file_name) = resolved.file_name() {
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with('.') {
                return Err(VoxError::HiddenDotfileBlocked(name_str.into_owned()));
            }
        }

        // Step 3 & 4: Discrete lowercase folder-block comparison against ALLOW and BLOCK rules
        let candidate_blocks = Self::to_discrete_lowercase_blocks(&resolved);

        if !self
            .allowed_block_rules
            .iter()
            .any(|rule| Self::matches_block_prefix(&candidate_blocks, rule))
        {
            return Err(VoxError::PathOutsideSandbox(
                resolved.to_string_lossy().into_owned(),
            ));
        }

        if self
            .blocked_block_rules
            .iter()
            .any(|rule| Self::matches_block_prefix(&candidate_blocks, rule))
        {
            return Err(VoxError::PathOutsideSandbox(
                resolved.to_string_lossy().into_owned(),
            ));
        }

        Ok(resolved)
    }

    /// Primary entry point for validating an enum base directory + relative path.
    pub fn validate_path(
        &self,
        base_enum: BaseDirEnum,
        relative_untrusted: Option<&str>,
        must_exist: bool,
    ) -> Result<PathBuf, VoxError> {
        let base_dir = base_enum.resolve_os_dir().ok_or_else(|| {
            VoxError::PathOutsideSandbox(format!("{:?}", base_enum))
        })?;
        self.validate_with_base_path(&base_dir, relative_untrusted, must_exist)
    }

    /// Walks up to the deepest existing ancestor directory, canonicalizes it via `dunce`,
    /// and re-appends the validated normal child components.
    fn canonicalize_non_existent(
        &self,
        base_dir: &Path,
        clean_rel_blocks: &[OsString],
    ) -> Result<PathBuf, VoxError> {
        let mut current = dunce::canonicalize(base_dir).map_err(|_| {
            VoxError::SourceNotFound(base_dir.to_string_lossy().into_owned())
        })?;

        let mut idx = 0;
        while idx < clean_rel_blocks.len() {
            let next_candidate = current.join(&clean_rel_blocks[idx]);
            if next_candidate.exists() {
                current = dunce::canonicalize(&next_candidate).map_err(|_| {
                    VoxError::PathOutsideSandbox(next_candidate.to_string_lossy().into_owned())
                })?;
                idx += 1;
            } else {
                break;
            }
        }

        for remaining in &clean_rel_blocks[idx..] {
            current.push(remaining);
        }

        Ok(current)
    }

    /// Returns true if the path has a high-risk executable/script extension (`.exe`, `.ps1`, `.bat`, `.sh`, etc.).
    pub fn is_high_risk_extension(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| self.high_risk_extensions.contains(ext.to_lowercase().as_str()))
            .unwrap_or(false)
    }

    /// FR-1 Step 6: Enforces the executable guard for FILE_MOVE, FILE_COPY, and FILE_RENAME.
    /// Moving/copying/renaming an executable or script outside Downloads is blocked.
    pub fn check_executable_mutation_guard(
        &self,
        source_path: &Path,
        destination_path: &Path,
        dest_base_enum: BaseDirEnum,
    ) -> Result<(), VoxError> {
        let src_risky = self.is_high_risk_extension(source_path);
        let dst_risky = self.is_high_risk_extension(destination_path);

        if (src_risky || dst_risky) && dest_base_enum != BaseDirEnum::Downloads {
            let offending = if dst_risky {
                destination_path
            } else {
                source_path
            };
            return Err(VoxError::ExecutableGuard(
                offending.to_string_lossy().into_owned(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_sandbox() -> (PathBuf, PathSandbox) {
        let root = std::env::temp_dir().join(format!("voxshell_sandbox_test_{}", uuid::Uuid::new_v4()));
        let docs = root.join("Documents");
        let downloads = root.join("Downloads");
        let ps_blocked = docs.join("PowerShell");

        fs::create_dir_all(&ps_blocked).unwrap();
        fs::create_dir_all(&downloads).unwrap();

        let canon_docs = dunce::canonicalize(&docs).unwrap();
        let canon_downloads = dunce::canonicalize(&downloads).unwrap();
        let canon_ps = dunce::canonicalize(&ps_blocked).unwrap();

        let sandbox = PathSandbox::with_custom_rules(
            vec![
                PathSandbox::to_discrete_lowercase_blocks(&canon_docs),
                PathSandbox::to_discrete_lowercase_blocks(&canon_downloads),
            ],
            vec![PathSandbox::to_discrete_lowercase_blocks(&canon_ps)],
        );

        (root, sandbox)
    }

    #[test]
    fn test_lexical_traversal_and_dotfile_blocked() {
        let (root, sandbox) = setup_test_sandbox();
        let docs = root.join("Documents");

        // 1. '..' traversal must fail in memory
        let res_traversal = sandbox.validate_with_base_path(&docs, Some("../etc/passwd"), false);
        assert!(matches!(res_traversal, Err(VoxError::PathTraversalDetected)));

        // 2. Hidden dotfile/dotfolder ('.ssh') must fail in memory
        let res_dotfile = sandbox.validate_with_base_path(&docs, Some(".ssh/id_rsa"), false);
        assert!(matches!(res_dotfile, Err(VoxError::HiddenDotfileBlocked(_))));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_discrete_block_matching_prevents_partial_folder_collision() {
        let (root, sandbox) = setup_test_sandbox();

        // Create a sibling folder 'Documents_Evil' that starts with the substring 'Documents'
        let docs_evil = root.join("Documents_Evil");
        fs::create_dir_all(&docs_evil).unwrap();

        let res = sandbox.validate_with_base_path(&docs_evil, Some("report.pdf"), false);
        assert!(
            matches!(res, Err(VoxError::PathOutsideSandbox(_))),
            "Documents_Evil must NOT match the Documents ALLOW block rule"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_case_insensitive_blocked_subdirectory_and_valid_non_existent_dest() {
        let (root, sandbox) = setup_test_sandbox();
        let docs = root.join("Documents");

        // 1. Attempting to write to 'powershell/profile.ps1' (lowercase) inside Documents must be blocked
        let blocked_res =
            sandbox.validate_with_base_path(&docs, Some("powershell/Microsoft.PowerShell_profile.ps1"), false);
        assert!(matches!(blocked_res, Err(VoxError::PathOutsideSandbox(_))));

        // 2. Valid non-existent destination 'Invoices/2026/receipt.pdf' inside Documents must succeed
        let valid_res =
            sandbox.validate_with_base_path(&docs, Some("Invoices/2026/receipt.pdf"), false);
        assert!(valid_res.is_ok());

        // 3. Executable guard blocks moving a .bat script into Documents
        let exec_res = sandbox.check_executable_mutation_guard(
            Path::new("cleanup.bat"),
            Path::new("Documents/cleanup.bat"),
            BaseDirEnum::Documents,
        );
        assert!(matches!(exec_res, Err(VoxError::ExecutableGuard(_))));

        let _ = fs::remove_dir_all(&root);
    }
}
