//! The reason `--dep` exists: code that uses crates.io cannot be type-checked
//! by a bare `rustc` shell-out, because the rlibs have to be built and passed
//! as `--extern` first.
//!
//! These tests talk to the network on a cold cache (Cargo fetches and builds
//! the requested crate once), then reuse it.

use rustcheck::{check, CheckOptions, Sandbox};

fn opts_with_deps(deps: &[&str]) -> CheckOptions {
    CheckOptions {
        // Keep the sandbox out of the picture: this test is about dependency
        // resolution, and bwrap is exercised by the CLI tests.
        sandbox: Sandbox::Off,
        timeout_ms: 30_000,
        deps: deps.iter().map(|d| d.to_string()).collect(),
        ..Default::default()
    }
}

const USES_SERDE_JSON: &str = r#"
use serde_json::json;

pub fn frame() -> serde_json::Value {
    json!({ "ether_type": 1, "payload": [] })
}
"#;

#[test]
fn without_dep_the_crate_is_unresolved() {
    let report = check(USES_SERDE_JSON, &CheckOptions { sandbox: Sandbox::Off, ..Default::default() });
    assert!(!report.success, "std-only check should not resolve serde_json");
    assert!(
        report.error_codes.iter().any(|c| c == "E0433" || c == "E0432"),
        "expected an unresolved-crate error, got {:?}",
        report.error_codes
    );
}

#[test]
fn with_dep_the_code_compiles() {
    let report = check(USES_SERDE_JSON, &opts_with_deps(&["serde_json@1"]));
    assert!(report.success, "codes: {:?}\nstderr: {}", report.error_codes, report.stderr);
}

#[test]
fn a_missing_crate_is_a_tooling_error_not_a_compile_error() {
    let report = check("pub fn ok() {}", &opts_with_deps(&["this-crate-does-not-exist-rustcheck@9.9"]));
    assert!(!report.success);
    assert!(
        report.error_codes.contains(&"E_DEPS".to_string()),
        "codes: {:?}",
        report.error_codes
    );
    assert_eq!(report.cli_exit_code(), 4);
}

#[test]
fn fix_works_with_dependencies_in_scope() {
    // The conversion error is repaired by the compiler's own suggestion, with
    // serde_json in scope — the repair loop must not lose the externs.
    let code = r#"
use serde_json::Value;

pub fn as_count(v: &Value) -> u16 {
    v["ether_type"].as_u64().unwrap_or(0)
}
"#;
    let broken = check(code, &opts_with_deps(&["serde_json@1"]));
    assert!(!broken.success, "the snippet was supposed to be broken");
    assert!(
        broken.error_codes.contains(&"E0308".to_string()),
        "codes: {:?}",
        broken.error_codes
    );

    let outcome = rustcheck::fix(code, &opts_with_deps(&["serde_json@1"]), 3);
    assert!(outcome.applied > 0, "no edit applied");
    assert!(
        outcome.report.success,
        "repair with externs in scope failed: {:?}\nstderr: {}",
        outcome.report.error_codes,
        outcome.report.stderr
    );
}
