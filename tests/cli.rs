//! End-to-end checks of the binary: exit codes and report shape.
//!
//! The unit tests in `src/lib.rs` call the library directly, so they never see
//! the exit-code taxonomy a pipeline actually depends on.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustcheck"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start rustcheck");
    child
        .stdin
        .take()
        .expect("no stdin")
        .write_all(stdin.as_bytes())
        .expect("failed to write stdin");
    let out = child.wait_with_output().expect("failed to read output");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn valid_snippet_exits_zero() {
    let (code, stdout, stderr) = run(&["check"], "pub fn add(a: i32, b: i32) -> i32 { a + b }");
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("pass"), "stdout: {stdout}");
}

#[test]
fn broken_snippet_exits_one_with_the_error_code() {
    let (code, stdout, _) = run(&["check"], "pub fn add(a: i32, b: i32) -> u16 { a + b }");
    assert_eq!(code, 1, "stdout: {stdout}");
    assert!(stdout.contains("E0308"), "stdout: {stdout}");
}

#[test]
fn guard_rejection_exits_two() {
    let (code, _, _) = run(&["check", "--guard"], "pub fn f(p: *const u8) -> u8 { unsafe { *p } }");
    assert_eq!(code, 2);
}

#[test]
fn usage_error_exits_sixty_four() {
    let (code, _, stderr) = run(&["check", "--not-a-flag"], "");
    assert_eq!(code, 64, "stderr: {stderr}");
}

#[test]
fn unreadable_file_is_a_tooling_error() {
    let (code, _, _) = run(&["check", "/nonexistent/no-such-file.rs"], "");
    assert_eq!(code, 4);
}

#[test]
fn malformed_dependency_spec_is_a_tooling_error() {
    // No network, no Cargo build: the spec is rejected before anything runs.
    let (code, stdout, _) = run(&["check", "--dep", "not a crate"], "pub fn ok() {}");
    assert_eq!(code, 4, "stdout: {stdout}");
    assert!(!stdout.contains("pass"), "stdout: {stdout}");
}

#[test]
fn json_report_parses_and_matches_the_exit_code() {
    let (code, stdout, _) = run(&["check", "--json"], "pub fn add(a: i32, b: i32) -> u16 { a + b }");
    assert_eq!(code, 1);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("report is not JSON");
    assert_eq!(value["success"], serde_json::Value::Bool(false));
    assert_eq!(value["sandbox"].as_str().is_some(), true);
    let codes = value["error_codes"].as_array().expect("error_codes is not an array");
    assert!(codes.iter().any(|c| c == "E0308"), "codes: {codes:?}");
}

#[test]
fn fix_repairs_the_snippet_and_prints_it() {
    let (code, stdout, stderr) = run(&["fix"], "pub fn add(a: i32, b: i32) -> u16 { a + b }");
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("try_into"), "stdout: {stdout}");
}

#[test]
fn fix_leaves_correct_code_alone() {
    let source = "pub fn add(a: i32, b: i32) -> i32 { a + b }\n";
    let (code, stdout, _) = run(&["fix"], source);
    assert_eq!(code, 0);
    assert_eq!(stdout, source);
}
