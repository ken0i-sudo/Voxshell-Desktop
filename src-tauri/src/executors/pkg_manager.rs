use crate::error::VoxError;
use async_trait::async_trait;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

pub const SUBPROCESS_TIMEOUT_SECS: u64 = 180; // FR-2: 180-second hard timeout
pub const WINGET_NO_USER_SCOPE_INSTALLER: i32 = -1978335215; // 0x8A150011

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageCandidate {
    pub package_id: String,
    pub package_name: String,
    pub version: String,
    pub source: String, // "winget" | "msstore" | "pacman" | "apt"
    pub exact_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgExecResult {
    pub package_manager: String, // "WINGET" | "PACMAN" | "APT"
    pub operation_type: String,  // "INSTALL" | "UNINSTALL" | "UPGRADE"
    pub package_id: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub triggered_uac_fallback: bool,
}

#[async_trait]
pub trait PackageManagerAdapter: Send + Sync {
    async fn search_packages(&self, query: &str) -> Result<Vec<PackageCandidate>, VoxError>;
    async fn install_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError>;
    async fn uninstall_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError>;
}

// ============================================================================
// WINDOWS ADAPTER: WingetAdapter (SADD-04 Locale-Independent Parser + SRS-01)
// ============================================================================
pub struct WingetAdapter;

impl WingetAdapter {
    /// SADD-04: Locale-independent parser for `winget search` output[cite: 4].
    /// Uses character-level indexing (not byte offsets) on the header row above the `---`
    /// separator so multi-byte UTF-8 headers (e.g. "Übereinstimmung") never shift ASCII data columns.
    pub fn parse_winget_search_output(stdout: &str, query: &str) -> Vec<PackageCandidate> {
        let lines: Vec<&str> = stdout
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .collect();

        // Rule 1 & 4: Find the separator line (>= 5 chars, only '-' and spaces, with a header above it)
        let sep_line_idx = lines.iter().enumerate().position(|(idx, line)| {
            let trimmed = line.trim();
            idx > 0
                && trimmed.len() >= 5
                && trimmed.starts_with("---")
                && trimmed.chars().all(|c| c == '-' || c == ' ')
                && !lines[idx - 1].trim().is_empty()
        });

        let Some(sep_idx) = sep_line_idx else {
            return Vec::new();
        };

        // Determine column character start indices from either spaced dashes OR the header row above
        let sep_line = lines[sep_idx];
        let header_line = lines[sep_idx - 1];

        let col_char_starts = if sep_line.trim().contains(' ') {
            Self::detect_char_starts_from_spaced_dashes(sep_line)
        } else {
            Self::detect_char_starts_from_header(header_line)
        };

        if col_char_starts.len() < 2 {
            return Vec::new();
        }

        let query_lower = query.trim().to_lowercase();
        let mut candidates = Vec::new();

        for data_line in &lines[(sep_idx + 1)..] {
            if data_line.trim().is_empty() {
                continue;
            }

            let name = Self::slice_by_char_range(data_line, &col_char_starts, 0);
            let id = Self::slice_by_char_range(data_line, &col_char_starts, 1);
            let version = if col_char_starts.len() > 2 {
                Self::slice_by_char_range(data_line, &col_char_starts, 2)
            } else {
                String::new()
            };
            let source = if col_char_starts.len() > 4 {
                Self::slice_by_char_range(data_line, &col_char_starts, 4)
            } else if col_char_starts.len() > 3 {
                Self::slice_by_char_range(data_line, &col_char_starts, 3)
            } else {
                "winget".to_string()
            };

            if id.is_empty() || name.is_empty() {
                continue;
            }

            let exact_match =
                id.to_lowercase() == query_lower || name.to_lowercase() == query_lower;

            candidates.push(PackageCandidate {
                package_id: id,
                package_name: name,
                version: if version.is_empty() || version == "Unknown" {
                    "latest".to_string()
                } else {
                    version
                },
                source: if source.is_empty() {
                    "winget".to_string()
                } else {
                    source
                },
                exact_match,
            });
        }

        candidates.sort_by(|a, b| {
            b.exact_match
                .cmp(&a.exact_match)
                .then_with(|| (a.source == "winget").cmp(&(b.source == "winget")).reverse())
        });

        candidates.truncate(5);
        candidates
    }

    /// Rule 3: Uses `.chars().enumerate()` (character positions, NOT byte offsets)
    /// so multi-byte characters like 'Ü' count as 1 column unit just like ASCII characters.
    fn detect_char_starts_from_header(header_line: &str) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut prev_is_space = true;

        for (char_idx, ch) in header_line.chars().enumerate() {
            if ch.is_whitespace() {
                prev_is_space = true;
            } else if prev_is_space {
                starts.push(char_idx);
                prev_is_space = false;
            }
        }
        starts
    }

    fn detect_char_starts_from_spaced_dashes(sep_line: &str) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut prev_is_space = true;

        for (char_idx, ch) in sep_line.chars().enumerate() {
            if ch == '-' {
                if prev_is_space {
                    starts.push(char_idx);
                    prev_is_space = false;
                }
            } else {
                prev_is_space = true;
            }
        }
        starts
    }

    /// Rule 3: Slices a line strictly by character index (`chars().skip().take()`),
    /// eliminating UTF-8 byte boundary panics and multi-byte offset drift.
    fn slice_by_char_range(line: &str, col_starts: &[usize], col_idx: usize) -> String {
        let start_char = col_starts[col_idx];
        let total_chars = line.chars().count();
        if start_char >= total_chars {
            return String::new();
        }

        let raw: String = if col_idx + 1 < col_starts.len() {
            let end_char = col_starts[col_idx + 1];
            let take_len = end_char.saturating_sub(start_char);
            line.chars().skip(start_char).take(take_len).collect()
        } else {
            line.chars().skip(start_char).collect()
        };

        raw.trim().to_string()
    }
}

#[async_trait]
impl PackageManagerAdapter for WingetAdapter {
    async fn search_packages(&self, query: &str) -> Result<Vec<PackageCandidate>, VoxError> {
        let args = vec![
            "search".to_string(),
            "--query".to_string(),
            query.to_string(),
            "--source".to_string(),
            "winget".to_string(),
            "--accept-source-agreements".to_string(),
        ];

        let (_, stdout, _) =
            run_headless_subprocess("winget", &args, CancellationToken::new()).await?;
        Ok(Self::parse_winget_search_output(&stdout, query))
    }

    async fn install_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError> {
        let user_scope_args = vec![
            "install".to_string(),
            "--id".to_string(),
            pkg_id.to_string(),
            "--exact".to_string(),
            "--scope".to_string(),
            "user".to_string(),
            "--silent".to_string(),
            "--accept-package-agreements".to_string(),
            "--accept-source-agreements".to_string(),
            "--disable-interactivity".to_string(),
        ];

        let (code, stdout, stderr) =
            run_headless_subprocess("winget", &user_scope_args, cancel.clone()).await?;

        if code == WINGET_NO_USER_SCOPE_INSTALLER {
            let fallback_args = vec![
                "install".to_string(),
                "--id".to_string(),
                pkg_id.to_string(),
                "--exact".to_string(),
                "--silent".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
                "--disable-interactivity".to_string(),
            ];
            let (fb_code, fb_stdout, fb_stderr) =
                run_headless_subprocess("winget", &fallback_args, cancel).await?;

            return Ok(PkgExecResult {
                package_manager: "WINGET".to_string(),
                operation_type: "INSTALL".to_string(),
                package_id: pkg_id.to_string(),
                argv: fallback_args,
                exit_code: fb_code,
                stdout: fb_stdout,
                stderr: fb_stderr,
                triggered_uac_fallback: true,
            });
        }

        Ok(PkgExecResult {
            package_manager: "WINGET".to_string(),
            operation_type: "INSTALL".to_string(),
            package_id: pkg_id.to_string(),
            argv: user_scope_args,
            exit_code: code,
            stdout,
            stderr,
            triggered_uac_fallback: false,
        })
    }

    async fn uninstall_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError> {
        let args = vec![
            "uninstall".to_string(),
            "--id".to_string(),
            pkg_id.to_string(),
            "--exact".to_string(),
            "--silent".to_string(),
            "--accept-source-agreements".to_string(),
            "--disable-interactivity".to_string(),
        ];

        let (code, stdout, stderr) = run_headless_subprocess("winget", &args, cancel).await?;

        Ok(PkgExecResult {
            package_manager: "WINGET".to_string(),
            operation_type: "UNINSTALL".to_string(),
            package_id: pkg_id.to_string(),
            argv: args,
            exit_code: code,
            stdout,
            stderr,
            triggered_uac_fallback: false,
        })
    }
}

// ============================================================================
// LINUX ADAPTER: Pacman (Arch/CachyOS) & APT (Debian/Ubuntu)
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxPkgBackend {
    Pacman,
    Apt,
}

pub struct LinuxPackageAdapter {
    pub backend: LinuxPkgBackend,
}

impl LinuxPackageAdapter {
    pub fn detect() -> Self {
        if std::path::Path::new("/usr/bin/pacman").exists() {
            Self {
                backend: LinuxPkgBackend::Pacman,
            }
        } else {
            Self {
                backend: LinuxPkgBackend::Apt,
            }
        }
    }

    pub fn parse_pacman_search_output(stdout: &str, query: &str) -> Vec<PackageCandidate> {
        let query_lower = query.trim().to_lowercase();
        let mut candidates = Vec::new();

        for line in stdout.lines() {
            if line.starts_with(' ') || line.starts_with('\t') || line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(repo_and_pkg) = parts.next() else {
                continue;
            };
            let version = parts.next().unwrap_or("latest").to_string();

            if let Some((_repo, pkg_name)) = repo_and_pkg.split_once('/') {
                let exact_match = pkg_name.to_lowercase() == query_lower;
                candidates.push(PackageCandidate {
                    package_id: pkg_name.to_string(),
                    package_name: pkg_name.to_string(),
                    version,
                    source: "pacman".to_string(),
                    exact_match,
                });
            }
        }

        candidates.sort_by(|a, b| b.exact_match.cmp(&a.exact_match));
        candidates.truncate(5);
        candidates
    }
}

#[async_trait]
impl PackageManagerAdapter for LinuxPackageAdapter {
    async fn search_packages(&self, query: &str) -> Result<Vec<PackageCandidate>, VoxError> {
        match self.backend {
            LinuxPkgBackend::Pacman => {
                let args = vec!["-Ss".to_string(), query.to_string()];
                let (_, stdout, _) =
                    run_headless_subprocess("pacman", &args, CancellationToken::new()).await?;
                Ok(Self::parse_pacman_search_output(&stdout, query))
            }
            LinuxPkgBackend::Apt => {
                let args = vec!["search".to_string(), query.to_string()];
                let (_, stdout, _) =
                    run_headless_subprocess("apt-cache", &args, CancellationToken::new()).await?;
                let query_lower = query.trim().to_lowercase();
                let mut candidates = Vec::new();
                for line in stdout.lines() {
                    if let Some((pkg, _desc)) = line.split_once(" - ") {
                        let pkg_trimmed = pkg.trim();
                        candidates.push(PackageCandidate {
                            package_id: pkg_trimmed.to_string(),
                            package_name: pkg_trimmed.to_string(),
                            version: "latest".to_string(),
                            source: "apt".to_string(),
                            exact_match: pkg_trimmed.to_lowercase() == query_lower,
                        });
                    }
                }
                candidates.sort_by(|a, b| b.exact_match.cmp(&a.exact_match));
                candidates.truncate(5);
                Ok(candidates)
            }
        }
    }

    async fn install_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError> {
        let (bin, mgr_name, args) = match self.backend {
            LinuxPkgBackend::Pacman => (
                "pkexec",
                "PACMAN",
                vec![
                    "pacman".to_string(),
                    "-S".to_string(),
                    "--noconfirm".to_string(),
                    pkg_id.to_string(),
                ],
            ),
            LinuxPkgBackend::Apt => (
                "pkexec",
                "APT",
                vec![
                    "apt-get".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    pkg_id.to_string(),
                ],
            ),
        };

        let (code, stdout, stderr) = run_headless_subprocess(bin, &args, cancel).await?;
        Ok(PkgExecResult {
            package_manager: mgr_name.to_string(),
            operation_type: "INSTALL".to_string(),
            package_id: pkg_id.to_string(),
            argv: args,
            exit_code: code,
            stdout,
            stderr,
            triggered_uac_fallback: false,
        })
    }

    async fn uninstall_package(
        &self,
        pkg_id: &str,
        cancel: CancellationToken,
    ) -> Result<PkgExecResult, VoxError> {
        let (bin, mgr_name, args) = match self.backend {
            LinuxPkgBackend::Pacman => (
                "pkexec",
                "PACMAN",
                vec![
                    "pacman".to_string(),
                    "-R".to_string(),
                    "--noconfirm".to_string(),
                    pkg_id.to_string(),
                ],
            ),
            LinuxPkgBackend::Apt => (
                "pkexec",
                "APT",
                vec![
                    "apt-get".to_string(),
                    "remove".to_string(),
                    "-y".to_string(),
                    pkg_id.to_string(),
                ],
            ),
        };

        let (code, stdout, stderr) = run_headless_subprocess(bin, &args, cancel).await?;
        Ok(PkgExecResult {
            package_manager: mgr_name.to_string(),
            operation_type: "UNINSTALL".to_string(),
            package_id: pkg_id.to_string(),
            argv: args,
            exit_code: code,
            stdout,
            stderr,
            triggered_uac_fallback: false,
        })
    }
}

pub fn record_package_operation(
    conn: &Connection,
    command_id: &str,
    res: &PkgExecResult,
) -> Result<(), VoxError> {
    let op_status = if res.exit_code == 0 {
        "SUCCESS"
    } else {
        "FAILED"
    };
    let argv_json = serde_json::to_string(&res.argv).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        "INSERT INTO package_operations (
            command_id, package_manager, operation_type, package_id, 
            package_source, argv_json, op_status
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command_id,
            res.package_manager,
            res.operation_type,
            res.package_id,
            res.package_manager.to_lowercase(),
            argv_json,
            op_status,
        ],
    )?;
    Ok(())
}

async fn run_headless_subprocess(
    program: &str,
    args: &[String],
    cancel: CancellationToken,
) -> Result<(i32, String, String), VoxError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(windows)]
    {
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }

    let child = cmd.spawn()?;
    let pid = child.id();
    let wait_fut = child.wait_with_output();

    tokio::select! {
        _ = cancel.cancelled() => {
            kill_process_tree(pid).await;
            Err(VoxError::SubprocessTimeout)
        }
        res = tokio::time::timeout(Duration::from_secs(SUBPROCESS_TIMEOUT_SECS), wait_fut) => {
            match res {
                Ok(Ok(output)) => {
                    let code = output.status.code().unwrap_or(-1);
                    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                    Ok((code, stdout, stderr))
                }
                Ok(Err(io_err)) => Err(VoxError::Io(io_err)),
                Err(_) => {
                    kill_process_tree(pid).await;
                    Err(VoxError::SubprocessTimeout)
                }
            }
        }
    }
}

async fn kill_process_tree(pid: Option<u32>) {
    let Some(pid_val) = pid else { return };
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid_val.to_string()])
            .creation_flags(0x0800_0000)
            .output()
            .await;
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-9", &pid_val.to_string()])
            .output()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_independent_winget_table_parser() {
        let sample_output = "\
Name                      ID                           Version  Übereinstimmung Quelle
---------------------------------------------------------------------------------------
Discord                   Discord.Discord              1.0.9168                 winget
Discord Canary            Discord.Discord.Canary       1.0.9012 Tag: discord    winget
Discord (Store)           9PFXXSH064H6                 Unknown                  msstore
";

        let parsed = WingetAdapter::parse_winget_search_output(sample_output, "Discord");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].package_id, "Discord.Discord");
        assert_eq!(parsed[0].version, "1.0.9168");
        assert_eq!(parsed[0].source, "winget");
        assert!(parsed[0].exact_match);
    }

    #[test]
    fn test_pacman_search_parser() {
        let pacman_out = "\
extra/discord 0.0.71-1 [installed]
    All-in-one voice and text chat for gamers
extra/discord-canary 0.0.510-1
    All-in-one voice and text chat for gamers (canary build)
";
        let parsed = LinuxPackageAdapter::parse_pacman_search_output(pacman_out, "discord");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].package_id, "discord");
        assert_eq!(parsed[0].version, "0.0.71-1");
        assert!(parsed[0].exact_match);
    }
}
