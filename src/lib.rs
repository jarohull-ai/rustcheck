//! `rustcheck` — verify that a snippet of Rust compiles, safely and quickly.
//!
//! Designed for the loop "model generates code → compiler judges it → model
//! repairs it". It type-checks through `rustc --emit=metadata`, optionally
//! inside a `bwrap` sandbox, with a hard wall-clock timeout, and returns
//! machine-readable diagnostics (error codes, levels, line/column).
//!
//! Differences from a plain `rustc` shell-out:
//! - the child runs in a network- and filesystem-isolated namespace when
//!   `bwrap` is available;
//! - stdout/stderr are drained by reader threads, so a large diagnostic dump
//!   cannot deadlock the pipe;
//! - the timeout kills the process instead of hanging on a macro bomb;
//! - diagnostics arrive as structured data, not regex over text.

use serde::Serialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Default wall-clock budget for one compilation.
pub const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Where the compile step is allowed to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    /// Use `bwrap` when it is installed, otherwise run directly.
    Auto,
    /// Require `bwrap`; fail if unavailable.
    Require,
    /// Never use a sandbox (fast local checks only).
    Off,
}

/// What kind of crate to type-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrateType {
    Lib,
    Bin,
}

impl CrateType {
    pub fn as_str(self) -> &'static str {
        match self {
            CrateType::Lib => "lib",
            CrateType::Bin => "bin",
        }
    }
}

/// Knobs for one verification run.
#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub edition: String,
    pub deny_warnings: bool,
    pub sandbox: Sandbox,
    pub timeout_ms: u64,
    /// Enable the static policy guard (rejects `unsafe`, networking, process
    /// spawning, filesystem destruction, unbounded loops).
    pub guard: bool,
    pub crate_type: CrateType,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            edition: "2021".to_string(),
            deny_warnings: false,
            sandbox: Sandbox::Auto,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            guard: false,
            crate_type: CrateType::Lib,
        }
    }
}

/// One compiler message, normalised across rustc's JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub level: String,
    pub code: Option<String>,
    pub message: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

/// Outcome of a verification run.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub success: bool,
    pub exit_code: i32,
    pub duration_ms: f64,
    /// `"bwrap"` or `"none"`.
    pub sandbox: String,
    pub timed_out: bool,
    pub safety_violation: Option<String>,
    pub error_codes: Vec<String>,
    pub errors: Vec<Diagnostic>,
    pub stderr: String,
}

impl CheckReport {
    /// Short human label: `pass`, `fail`, `safety`, `timeout`.
    pub fn status(&self) -> &'static str {
        if self.safety_violation.is_some() {
            "safety"
        } else if self.timed_out {
            "timeout"
        } else if self.success {
            "pass"
        } else {
            "fail"
        }
    }
}

/// Static policy check applied before the compiler runs.
///
/// This is a coarse gate, not a security boundary — the sandbox is the
/// boundary. Enable it only when the code under test is untrusted *and* is
/// expected to stay pure (no `unsafe`, no I/O).
pub fn guard_violation(code: &str) -> Option<&'static str> {
    let lower = code.to_lowercase();
    let banned: [(&str, &str); 8] = [
        ("unsafe {", "unsafe block"),
        ("unsafe fn", "unsafe function"),
        ("process::command", "process spawning (std::process::Command)"),
        ("std::net", "networking (std::net)"),
        ("tcpstream", "networking (TcpStream)"),
        ("remove_dir_all", "filesystem destruction (remove_dir_all)"),
        ("rm -rf", "filesystem destruction (rm -rf)"),
        ("while true", "unbounded loop (while true)"),
    ];
    for (needle, label) in banned {
        if lower.contains(needle) {
            return Some(label);
        }
    }
    None
}

fn bwrap_available() -> bool {
    Path::new("/usr/bin/bwrap").exists()
}

fn temp_rmeta_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("rustcheck_{}_{}.rmeta", std::process::id(), nanos))
}

fn spawn_reader<T: Read + Send + 'static>(mut pipe: T) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

/// Compile `code` and report the result. Never panics on compiler output.
pub fn check(code: &str, opts: &CheckOptions) -> CheckReport {
    let start = Instant::now();

    if opts.guard {
        if let Some(violation) = guard_violation(code) {
            return CheckReport {
                success: false,
                exit_code: -99,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                sandbox: "none".to_string(),
                timed_out: false,
                safety_violation: Some(violation.to_string()),
                error_codes: vec!["E_SAFETY".to_string()],
                errors: vec![Diagnostic {
                    level: "error".to_string(),
                    code: Some("E_SAFETY".to_string()),
                    message: format!("rejected by policy guard: {violation}"),
                    line: None,
                    column: None,
                }],
                stderr: String::new(),
            };
        }
    }

    let rmeta = temp_rmeta_path();
    let use_bwrap = match opts.sandbox {
        Sandbox::Off => false,
        Sandbox::Auto => bwrap_available(),
        Sandbox::Require => bwrap_available(),
    };

    if matches!(opts.sandbox, Sandbox::Require) && !use_bwrap {
        return CheckReport {
            success: false,
            exit_code: -98,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            sandbox: "none".to_string(),
            timed_out: false,
            safety_violation: None,
            error_codes: vec!["E_NO_SANDBOX".to_string()],
            errors: vec![Diagnostic {
                level: "error".to_string(),
                code: Some("E_NO_SANDBOX".to_string()),
                message: "bwrap is required but not installed".to_string(),
                line: None,
                column: None,
            }],
            stderr: String::new(),
        };
    }

    let mut cmd = if use_bwrap {
        let mut c = Command::new("/usr/bin/bwrap");
        c.arg("--unshare-all")
            .arg("--die-with-parent")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--ro-bind-try")
            .arg("/lib")
            .arg("/lib")
            .arg("--ro-bind-try")
            .arg("/lib64")
            .arg("/lib64")
            .arg("--ro-bind-try")
            .arg("/bin")
            .arg("/bin")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--setenv")
            .arg("PATH")
            .arg("/usr/bin:/bin")
            .arg("rustc");
        c
    } else {
        Command::new("rustc")
    };

    cmd.arg("--crate-type")
        .arg(opts.crate_type.as_str())
        .arg("--emit=metadata")
        .arg("-o")
        .arg(&rmeta)
        .arg(format!("--edition={}", opts.edition))
        .arg("--error-format=json");

    if opts.deny_warnings {
        cmd.arg("-D").arg("warnings");
    }

    cmd.arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CheckReport {
                success: false,
                exit_code: -97,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                sandbox: if use_bwrap { "bwrap" } else { "none" }.to_string(),
                timed_out: false,
                safety_violation: None,
                error_codes: vec!["E_NO_RUSTC".to_string()],
                errors: vec![Diagnostic {
                    level: "error".to_string(),
                    code: Some("E_NO_RUSTC".to_string()),
                    message: format!("could not start compiler: {e}"),
                    line: None,
                    column: None,
                }],
                stderr: String::new(),
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(code.as_bytes());
        // stdin drops here, signalling EOF to rustc.
    }

    // Drain pipes on separate threads: rustc can emit far more than a pipe
    // buffer holds, and reading only after exit would deadlock.
    let out_reader = child.stdout.take().map(spawn_reader);
    let err_reader = child.stderr.take().map(spawn_reader);

    let deadline = Duration::from_millis(opts.timeout_ms.max(100));
    let mut timed_out = false;
    let mut status_code: Option<i32> = None;

    while start.elapsed() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                status_code = status.code();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }

    if status_code.is_none() && !child.try_wait().map(|s| s.is_some()).unwrap_or(false) {
        let _ = child.kill();
        let _ = child.wait();
        timed_out = true;
    }

    let stdout_bytes = out_reader.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let stderr_bytes = err_reader.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let _ = std::fs::remove_file(&rmeta);

    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    if timed_out {
        return CheckReport {
            success: false,
            exit_code: -1,
            duration_ms,
            sandbox: if use_bwrap { "bwrap" } else { "none" }.to_string(),
            timed_out: true,
            safety_violation: None,
            error_codes: vec!["E_TIMEOUT".to_string()],
            errors: vec![Diagnostic {
                level: "error".to_string(),
                code: Some("E_TIMEOUT".to_string()),
                message: format!(
                    "compilation exceeded {} ms and was killed (macro bomb or hang)",
                    opts.timeout_ms
                ),
                line: None,
                column: None,
            }],
            stderr,
        };
    }

    let (diagnostics, rendered) = parse_diagnostics(&stderr);
    let mut error_codes: Vec<String> = Vec::new();
    for d in &diagnostics {
        if d.level == "error" {
            if let Some(code) = &d.code {
                if !error_codes.contains(code) {
                    error_codes.push(code.clone());
                }
            }
        }
    }
    for token in stderr.split_whitespace() {
        // Fallback for non-JSON lines (e.g. linker or driver errors).
        if token.starts_with('E') && token.len() == 5 && token[1..].chars().all(|c| c.is_ascii_digit()) {
            let code = token.to_string();
            if !error_codes.contains(&code) {
                error_codes.push(code);
            }
        }
    }

    // `aborting due to N previous errors` is rustc's summary line, not a
    // diagnostic of its own — drop it so callers do not double-count errors.
    let errors: Vec<Diagnostic> = diagnostics
        .into_iter()
        .filter(|d| d.level == "error" && !d.message.starts_with("aborting due to"))
        .collect();
    let success = status_code == Some(0);

    // Human-readable text: rustc's own rendering when we have it, otherwise
    // whatever non-JSON lines the driver emitted (linker errors, panics).
    let plain_stderr: String = stderr
        .lines()
        .filter(|l| !l.trim_start().starts_with('{'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut stderr_text = if rendered.trim().is_empty() { plain_stderr } else { rendered };
    if !stdout.trim().is_empty() {
        stderr_text = format!("{stderr_text}\n{stdout}");
    }

    CheckReport {
        success,
        exit_code: status_code.unwrap_or(-1),
        duration_ms,
        sandbox: if use_bwrap { "bwrap" } else { "none" }.to_string(),
        timed_out: false,
        safety_violation: None,
        error_codes,
        errors,
        stderr: stderr_text,
    }
}

/// Parse rustc's `--error-format=json` stream, ignoring non-JSON noise.
fn parse_diagnostics(stderr: &str) -> (Vec<Diagnostic>, String) {
    let mut out = Vec::new();
    let mut rendered_parts: Vec<String> = Vec::new();
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Plain `rustc --error-format=json` emits `{"$message_type":"diagnostic",..}`
        // directly, while `--message-format=json` (cargo) wraps it in
        // `{"reason":"compiler-message","message":{..}}`. Accept both.
        let msg: serde_json::Value =
            if value.get("reason").and_then(|r| r.as_str()) == Some("compiler-message") {
                match value.get("message") {
                    Some(m) => m.clone(),
                    None => continue,
                }
            } else if value.get("$message_type").and_then(|m| m.as_str()) == Some("diagnostic") {
                value.clone()
            } else {
                continue;
            };
        let level = msg.get("level").and_then(|l| l.as_str()).unwrap_or("error").to_string();
        let message = msg.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let code = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let (line_no, column) = msg
            .get("spans")
            .and_then(|s| s.as_array())
            .and_then(|arr| arr.first())
            .map(|span| {
                (
                    span.get("line_start").and_then(|v| v.as_u64()).map(|v| v as u32),
                    span.get("column_start").and_then(|v| v.as_u64()).map(|v| v as u32),
                )
            })
            .unwrap_or((None, None));
        if let Some(r) = msg.get("rendered").and_then(|r| r.as_str()) {
            if !r.trim().is_empty() {
                rendered_parts.push(r.to_string());
            }
        }
        out.push(Diagnostic { level, code, message, line: line_no, column });
    }
    (out, rendered_parts.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CheckOptions {
        CheckOptions { sandbox: Sandbox::Off, timeout_ms: 10_000, ..Default::default() }
    }

    #[test]
    fn accepts_valid_code() {
        let report = check("pub fn add(a: i32, b: i32) -> i32 { a + b }", &opts());
        assert!(report.success, "stderr: {}", report.stderr);
        assert!(report.error_codes.is_empty());
    }

    #[test]
    fn reports_type_mismatch_with_code() {
        let report = check("pub fn add(a: i32, b: i32) -> u16 { a + b }", &opts());
        assert!(!report.success);
        assert!(report.error_codes.contains(&"E0308".to_string()), "codes: {:?}", report.error_codes);
        assert!(report.errors.iter().any(|d| d.line.is_some()), "no span parsed");
    }

    #[test]
    fn guard_rejects_unsafe() {
        let mut o = opts();
        o.guard = true;
        let report = check("pub fn f(p: *const u8) -> u8 { unsafe { *p } }", &o);
        assert_eq!(report.status(), "safety");
        assert_eq!(report.error_codes, vec!["E_SAFETY".to_string()]);
    }

    #[test]
    fn deny_warnings_turns_warning_into_error() {
        let mut o = opts();
        o.deny_warnings = true;
        let report = check("pub fn f() { let unused = 1; }", &o);
        assert!(!report.success);
    }
}
