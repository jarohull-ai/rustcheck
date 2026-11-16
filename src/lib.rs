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

mod deps;

/// Where resolved crate artifacts are cached
/// (`$XDG_CACHE_HOME/rustcheck`, `~/.cache/rustcheck` or `$RUSTCHECK_CACHE_DIR`).
pub use deps::cache_root as deps_cache_dir;

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
    /// Build as a test harness (`rustc --test`), so `#[test]` functions and
    /// the harness around them are type-checked too.
    Test,
}

impl CrateType {
    pub fn as_str(self) -> &'static str {
        match self {
            CrateType::Lib => "lib",
            CrateType::Bin => "bin",
            CrateType::Test => "test",
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
    /// Registry crates the snippet uses, as `--dep` specs: `serde`,
    /// `serde-json@1.0`. Empty means std-only, which needs no Cargo at all.
    pub deps: Vec<String>,
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
            deps: Vec::new(),
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

/// A machine-applicable edit proposed by the compiler.
///
/// Byte offsets refer to the source that produced this report, so they are
/// only valid for that exact string.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub byte_start: u32,
    pub byte_end: u32,
    pub replacement: String,
    pub applicability: String,
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

    /// Exit code for the CLI, following the documented taxonomy:
    /// 0 pass, 1 the code is broken, 2 policy guard, 3 timeout,
    /// 4 the tool could not do its job (no rustc, no bwrap when required,
    /// dependencies that would not resolve, unreadable input).
    ///
    /// A harness cares about that last distinction: "the model wrote bad
    /// code" and "the verifier is broken" must not look the same.
    pub fn cli_exit_code(&self) -> u8 {
        const TOOLING: [&str; 5] = ["E_NO_RUSTC", "E_NO_SANDBOX", "E_NO_CARGO", "E_DEPS", "E_BAD_DEP"];
        if self.safety_violation.is_some() {
            2
        } else if self.timed_out {
            3
        } else if self.error_codes.iter().any(|code| TOOLING.contains(&code.as_str())) {
            4
        } else if self.success {
            0
        } else {
            1
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

/// Absolute path of `rustc` as this process would run it.
fn rustc_path() -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join("rustc"))
        .find(|candidate| candidate.is_file())
}

/// Bind `dir` read-only unless it is already covered by a broader bind.
fn bind_ro(cmd: &mut Command, dir: &Path, bound: &mut Vec<PathBuf>) {
    if !dir.exists() || bound.iter().any(|seen| seen == dir) {
        return;
    }
    cmd.arg("--ro-bind").arg(dir).arg(dir);
    bound.push(dir.to_path_buf());
}

/// The sandbox prefix shared by the probe and by real checks.
///
/// Only `/usr`, the C-library directories, the Rust toolchain and the given
/// extra directories are readable. Binding the whole filesystem would be
/// simpler, but a snippet can write `include_str!("/home/you/.ssh/id_rsa")`
/// and rustc would read it straight into a diagnostic — the compiler must not
/// see what the snippet has no business seeing.
///
/// A rustup-installed `rustc` lives in `$CARGO_HOME/bin` and needs
/// `$RUSTUP_HOME`; a distro `rustc` lives in `/usr/bin` and needs nothing.
/// Getting this wrong silently breaks every check on machines with rustup, so
/// the paths are resolved from the toolchain rather than assumed.
fn bwrap_command(extra: &[PathBuf]) -> Command {
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.arg("--unshare-all")
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
        .arg("/dev");

    let mut bound: Vec<PathBuf> = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/bin"),
    ];

    let mut path_entries: Vec<PathBuf> = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
    if let Some(rustc) = rustc_path() {
        if let Some(dir) = rustc.parent() {
            bind_ro(&mut cmd, dir, &mut bound);
            path_entries.insert(0, dir.to_path_buf());
        }
    }
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
    if let Some(dir) = rustup_home {
        bind_ro(&mut cmd, &dir, &mut bound);
    }
    for dir in extra {
        bind_ro(&mut cmd, dir, &mut bound);
    }

    // Keep the sandbox PATH equal to the host's toolchain location, so the
    // `rustc` the caller would run is the `rustc` that runs here.
    let path_value = std::env::join_paths(path_entries)
        .unwrap_or_else(|_| std::ffi::OsString::from("/usr/bin:/bin"));
    cmd.arg("--setenv").arg("PATH").arg(path_value);
    cmd
}

/// Does the sandbox actually work here — not just `bwrap` exist?
///
/// Two ways it lies: unprivileged user namespaces can be blocked
/// (Ubuntu 23.10+ via AppArmor), and the toolchain can sit outside the paths
/// the sandbox exposes (rustup). Either one turns valid code into `fail`, the
/// one answer a verifier must never give, so probe by running the real
/// compiler through the real sandbox once per process.
fn bwrap_usable() -> bool {
    static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        if !bwrap_available() {
            return false;
        }
        let status = bwrap_command(&[])
            .arg("rustc")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        matches!(status, Ok(status) if status.success())
    })
}

/// `(installed, usable)` — for `rustcheck doctor`, so the reason is visible.
pub fn bwrap_status() -> (bool, bool) {
    (bwrap_available(), bwrap_usable())
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
    check_full(code, opts).0
}

/// Like [`check`], but also returns the edits rustc proposed — the input for
/// [`apply_suggestions`] and [`fix`].
pub fn check_full(code: &str, opts: &CheckOptions) -> (CheckReport, Vec<Suggestion>) {
    let start = Instant::now();

    if opts.guard {
        if let Some(violation) = guard_violation(code) {
            return (CheckReport {
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
            }, Vec::new());
        }
    }

    // External crates need Cargo to build their rlibs before rustc can see
    // them. Failure here is a tooling problem, not a verdict on the code.
    let dep_env = if opts.deps.is_empty() {
        None
    } else {
        match deps::resolve_specs(&opts.deps, &opts.edition) {
            Ok(env) => Some(env),
            Err((code, message)) => {
                return (
                    CheckReport {
                        success: false,
                        exit_code: -96,
                        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                        sandbox: "none".to_string(),
                        timed_out: false,
                        safety_violation: None,
                        error_codes: vec![code.to_string()],
                        errors: vec![Diagnostic {
                            level: "error".to_string(),
                            code: Some(code.to_string()),
                            message,
                            line: None,
                            column: None,
                        }],
                        stderr: String::new(),
                    },
                    Vec::new(),
                );
            }
        }
    };

    let rmeta = temp_rmeta_path();
    let use_bwrap = match opts.sandbox {
        Sandbox::Off => false,
        Sandbox::Auto | Sandbox::Require => bwrap_usable(),
    };

    if matches!(opts.sandbox, Sandbox::Require) && !use_bwrap {
        return (CheckReport {
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
                message: if bwrap_available() {
                    "bwrap is required but unusable here: it is installed, yet it cannot create a sandbox (unprivileged user namespaces are probably blocked). Run `rustcheck doctor` for details.".to_string()
                } else {
                    "bwrap is required but not installed".to_string()
                },
                line: None,
                column: None,
            }],
            stderr: String::new(),
        }, Vec::new());
    }

    // Dependency artifacts live outside the sandbox root (the user's cache),
    // so they are bound in explicitly — read-only, nothing else.
    let dep_dirs: &[PathBuf] = dep_env
        .as_ref()
        .map(|env| env.lib_dirs.as_slice())
        .unwrap_or(&[]);
    let mut cmd = if use_bwrap {
        let mut c = bwrap_command(dep_dirs);
        c.arg("rustc");
        c
    } else {
        Command::new("rustc")
    };

    if opts.crate_type == CrateType::Test {
        cmd.arg("--test");
    } else {
        cmd.arg("--crate-type").arg(opts.crate_type.as_str());
    }
    cmd.arg("--emit=metadata")
        .arg("-o")
        .arg(&rmeta)
        .arg(format!("--edition={}", opts.edition))
        .arg("--error-format=json");

    if let Some(env) = &dep_env {
        for dir in &env.lib_dirs {
            cmd.arg("-L").arg(format!("dependency={}", dir.display()));
        }
        for (name, path) in &env.externs {
            cmd.arg("--extern").arg(format!("{name}={}", path.display()));
        }
    }

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
            return (CheckReport {
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
            }, Vec::new());
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
        return (CheckReport {
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
        }, Vec::new());
    }

    let (diagnostics, rendered, suggestions) = parse_diagnostics(&stderr);
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

    let report = CheckReport {
        success,
        exit_code: status_code.unwrap_or(-1),
        duration_ms,
        sandbox: if use_bwrap { "bwrap" } else { "none" }.to_string(),
        timed_out: false,
        safety_violation: None,
        error_codes,
        errors,
        stderr: stderr_text,
    };
    (report, suggestions)
}

/// Apply rustc's machine-applicable suggestions to `code`.
///
/// Edits are applied from the end of the source backwards so earlier offsets
/// stay valid; overlapping edits are skipped. Returns the rewritten source and
/// how many edits were applied.
pub fn apply_suggestions(code: &str, suggestions: &[Suggestion]) -> (String, usize) {
    let mut edits: Vec<&Suggestion> = suggestions
        .iter()
        .filter(|s| s.applicability == "MachineApplicable")
        .filter(|s| {
            let (end, start) = (s.byte_end as usize, s.byte_start as usize);
            end <= code.len() && start <= end && code.is_char_boundary(start) && code.is_char_boundary(end)
        })
        .collect();
    edits.sort_by_key(|s| std::cmp::Reverse(s.byte_start));

    let mut out = code.to_string();
    let mut applied = 0usize;
    let mut boundary = usize::MAX;

    for edit in edits {
        let (start, end) = (edit.byte_start as usize, edit.byte_end as usize);
        if end > boundary {
            continue;
        }
        out.replace_range(start..end, &edit.replacement);
        boundary = start;
        applied += 1;
    }

    (out, applied)
}

/// Result of an iterative repair attempt.
#[derive(Debug, Clone)]
pub struct FixOutcome {
    pub code: String,
    pub report: CheckReport,
    pub applied: usize,
    pub rounds: usize,
}

/// Compile, apply the compiler's own suggestions, repeat.
///
/// This repairs purely mechanical defects (type conversions, missing `mut`,
/// wrong argument order) without any model in the loop.
pub fn fix(code: &str, opts: &CheckOptions, max_rounds: usize) -> FixOutcome {
    let mut current = code.to_string();
    let mut applied_total = 0usize;
    let mut rounds = 0usize;
    let mut report = check(&current, opts);

    while !report.success && rounds < max_rounds {
        let (_, suggestions) = check_full(&current, opts);
        let (next, applied) = apply_suggestions(&current, &suggestions);
        if applied == 0 || next == current {
            break;
        }
        current = next;
        applied_total += applied;
        rounds += 1;
        report = check(&current, opts);
    }

    FixOutcome { code: current, report, applied: applied_total, rounds }
}

/// Parse rustc's `--error-format=json` stream, ignoring non-JSON noise.
fn parse_diagnostics(stderr: &str) -> (Vec<Diagnostic>, String, Vec<Suggestion>) {
    let mut out = Vec::new();
    let mut rendered_parts: Vec<String> = Vec::new();
    let mut suggestions: Vec<Suggestion> = Vec::new();
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
        collect_suggestions(&msg, &mut suggestions);
        out.push(Diagnostic { level, code, message, line: line_no, column });
    }
    (out, rendered_parts.join("\n"), suggestions)
}

/// Collect machine-applicable edits from a diagnostic's spans and children.
fn collect_suggestions(msg: &serde_json::Value, out: &mut Vec<Suggestion>) {
    fn push_spans(node: &serde_json::Value, out: &mut Vec<Suggestion>) {
        let Some(spans) = node.get("spans").and_then(|s| s.as_array()) else {
            return;
        };
        for span in spans {
            let Some(replacement) = span.get("suggested_replacement").and_then(|r| r.as_str()) else {
                continue;
            };
            let applicability = span
                .get("suggestion_applicability")
                .and_then(|a| a.as_str())
                .unwrap_or("Unspecified");
            let (Some(byte_start), Some(byte_end)) = (
                span.get("byte_start").and_then(|v| v.as_u64()),
                span.get("byte_end").and_then(|v| v.as_u64()),
            ) else {
                continue;
            };
            out.push(Suggestion {
                byte_start: byte_start as u32,
                byte_end: byte_end as u32,
                replacement: replacement.to_string(),
                applicability: applicability.to_string(),
            });
        }
    }

    push_spans(msg, out);
    if let Some(children) = msg.get("children").and_then(|c| c.as_array()) {
        for child in children {
            push_spans(child, out);
        }
    }
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

    #[test]
    fn fix_repairs_type_mismatch_without_a_model() {
        let outcome = fix("pub fn add(a: i32, b: i32) -> u16 { a + b }", &opts(), 3);
        assert!(outcome.report.success, "still broken: {}", outcome.report.stderr);
        assert!(outcome.applied > 0, "no edit applied");
        assert!(outcome.code.contains("try_into"), "unexpected result: {}", outcome.code);
    }

    #[test]
    fn valid_code_passes_whatever_the_sandbox_does() {
        // Regression: a present-but-broken bwrap used to turn valid code into
        // `fail` (exit 1) instead of running unsandboxed.
        let report = check("pub fn ok() -> u8 { 1 }", &CheckOptions::default());
        assert!(
            report.success,
            "sandbox: {}, codes: {:?}, stderr: {}",
            report.sandbox,
            report.error_codes,
            report.stderr
        );
    }

    #[test]
    fn test_harness_is_type_checked() {
        let mut o = opts();
        o.crate_type = CrateType::Test;
        let code = "pub fn add(a: i32, b: i32) -> i32 { a + b }\n#[test]\nfn t() { assert_eq!(add(1, 2), 3); }";
        let report = check(code, &o);
        assert!(report.success, "stderr: {}", report.stderr);
    }
}
