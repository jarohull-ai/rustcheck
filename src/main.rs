use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use rustcheck::{check, fix, CheckOptions, CrateType, Sandbox};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "rustcheck",
    version,
    about = "Sandboxed Rust compile verification: fast pass/fail plus structured diagnostics for generated code"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Type-check a Rust snippet read from a file or stdin.
    Check {
        /// Path to a .rs file. Omit to read stdin.
        file: Option<PathBuf>,

        /// Machine-readable report on stdout.
        #[arg(long)]
        json: bool,

        /// Rust edition to compile with.
        #[arg(long, default_value = "2021")]
        edition: String,

        /// Treat warnings as errors (-D warnings).
        #[arg(long)]
        deny_warnings: bool,

        /// Reject unsafe, networking, process spawning, unbounded loops.
        #[arg(long)]
        guard: bool,

        /// Skip the bwrap sandbox even if it is installed.
        #[arg(long)]
        no_sandbox: bool,

        /// Fail if bwrap is unavailable instead of running unsandboxed.
        #[arg(long)]
        require_sandbox: bool,

        /// Wall-clock budget for the compiler, in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,

        /// Crate type to build metadata for (`test` type-checks #[test] harnesses).
        #[arg(long, value_parser = ["lib", "bin", "test"], default_value = "lib")]
        crate_type: String,

        /// Registry crate the snippet uses: `--dep serde` or
        /// `--dep serde-json@1.0`. Repeat for several crates.
        #[arg(long = "dep", value_name = "SPEC")]
        deps: Vec<String>,
    },

    /// Apply the compiler's own suggestions until the code type-checks.
    Fix {
        /// Path to a .rs file. Omit to read stdin.
        file: Option<PathBuf>,

        /// Overwrite the input file instead of printing to stdout.
        #[arg(long)]
        write: bool,

        /// Machine-readable report plus the repaired source.
        #[arg(long)]
        json: bool,

        /// Rust edition to compile with.
        #[arg(long, default_value = "2021")]
        edition: String,

        /// Treat warnings as errors (-D warnings).
        #[arg(long)]
        deny_warnings: bool,

        /// Registry crate the snippet uses: `--dep serde` or
        /// `--dep serde-json@1.0`. Repeat for several crates.
        #[arg(long = "dep", value_name = "SPEC")]
        deps: Vec<String>,

        /// How many repair rounds to attempt.
        #[arg(long, default_value_t = 5)]
        max_rounds: usize,

        /// Wall-clock budget per compilation, in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,

        /// Skip the bwrap sandbox even if it is installed.
        #[arg(long)]
        no_sandbox: bool,
    },

    /// Report toolchain and sandbox availability.
    Doctor,
}

fn read_code(file: &Option<PathBuf>) -> Result<String, String> {
    match file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display())),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("cannot read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn main() -> ExitCode {
    // Parse by hand so a usage error cannot be confused with a policy-guard
    // rejection: clap's default failure code is 2, which is our "safety".
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let kind = err.kind();
            let _ = err.print();
            return if matches!(kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(64)
            };
        }
    };

    match cli.cmd {
        Cmd::Check {
            file,
            json,
            edition,
            deny_warnings,
            guard,
            no_sandbox,
            require_sandbox,
            timeout_ms,
            crate_type,
            deps,
        } => {
            let code = match read_code(&file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("rustcheck: {e}");
                    return ExitCode::from(4);
                }
            };

            let sandbox = if no_sandbox {
                Sandbox::Off
            } else if require_sandbox {
                Sandbox::Require
            } else {
                Sandbox::Auto
            };

            let opts = CheckOptions {
                edition,
                deny_warnings,
                sandbox,
                timeout_ms,
                guard,
                crate_type: match crate_type.as_str() {
                    "bin" => CrateType::Bin,
                    "test" => CrateType::Test,
                    _ => CrateType::Lib,
                },
                deps,
            };

            let report = check(&code, &opts);

            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("rustcheck: cannot serialize report: {e}");
                        return ExitCode::from(4);
                    }
                }
            } else if report.success {
                println!(
                    "✓ pass  ({} ms, sandbox: {})",
                    report.duration_ms.round(),
                    report.sandbox
                );
            } else {
                println!(
                    "✗ {}  ({} ms, sandbox: {})",
                    report.status(),
                    report.duration_ms.round(),
                    report.sandbox
                );
                if let Some(violation) = &report.safety_violation {
                    println!("  E_SAFETY: {violation}");
                }
                for diag in &report.errors {
                    let code = diag.code.as_deref().unwrap_or("error");
                    let loc = match (diag.line, diag.column) {
                        (Some(l), Some(c)) => format!("{l}:{c}"),
                        (Some(l), None) => format!("{l}"),
                        _ => "-".to_string(),
                    };
                    println!("  [{code}] {loc}: {}", diag.message.lines().next().unwrap_or(""));
                    // Tooling errors (E_DEPS, E_NO_CARGO) carry the whole Cargo
                    // or driver message; truncating it hides the actual cause.
                    for line in diag.message.lines().skip(1).take(8) {
                        println!("      {line}");
                    }
                }
                if report.errors.is_empty() && !report.stderr.trim().is_empty() {
                    for line in report.stderr.lines().take(10) {
                        println!("  {line}");
                    }
                }
            }

            ExitCode::from(report.cli_exit_code())
        }

        Cmd::Fix {
            file,
            write,
            json,
            edition,
            deny_warnings,
            deps,
            max_rounds,
            timeout_ms,
            no_sandbox,
        } => {
            let code = match read_code(&file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("rustcheck: {e}");
                    return ExitCode::from(4);
                }
            };

            let opts = CheckOptions {
                edition,
                deny_warnings,
                sandbox: if no_sandbox { Sandbox::Off } else { Sandbox::Auto },
                timeout_ms,
                guard: false,
                crate_type: CrateType::Lib,
                deps,
            };

            let outcome = fix(&code, &opts, max_rounds);

            if json {
                let payload = serde_json::json!({
                    "success": outcome.report.success,
                    "applied_edits": outcome.applied,
                    "rounds": outcome.rounds,
                    "code": outcome.code,
                    "report": outcome.report,
                });
                match serde_json::to_string_pretty(&payload) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("rustcheck: cannot serialize result: {e}");
                        return ExitCode::from(4);
                    }
                }
            } else {
                eprintln!(
                    "rustcheck: applied {} edit(s) in {} round(s) -> {}",
                    outcome.applied,
                    outcome.rounds,
                    outcome.report.status()
                );
                if write {
                    if let Some(path) = &file {
                        if let Err(e) = std::fs::write(path, &outcome.code) {
                            eprintln!("rustcheck: cannot write {}: {e}", path.display());
                            return ExitCode::from(4);
                        }
                    } else {
                        eprintln!("rustcheck: --write needs a file argument; printing instead");
                        print!("{}", outcome.code);
                    }
                } else {
                    print!("{}", outcome.code);
                }
            }

            ExitCode::from(outcome.report.cli_exit_code())
        }

        Cmd::Doctor => {
            let rustc = std::process::Command::new("rustc").arg("--version").output();
            match rustc {
                Ok(out) if out.status.success() => {
                    println!("rustc:  {}", String::from_utf8_lossy(&out.stdout).trim());
                }
                _ => println!("rustc:  NOT FOUND (verification is impossible)"),
            }

            let bwrap = std::process::Command::new("/usr/bin/bwrap").arg("--version").output();
            match bwrap {
                Ok(out) if out.status.success() => {
                    println!("bwrap:  {}", String::from_utf8_lossy(&out.stdout).trim());
                }
                _ => println!("bwrap:  not installed (checks run unsandboxed)"),
            }

            let cargo = std::process::Command::new("cargo").arg("--version").output();
            match cargo {
                Ok(out) if out.status.success() => {
                    println!("cargo:  {} (needed for --dep)", String::from_utf8_lossy(&out.stdout).trim());
                }
                _ => println!("cargo:  NOT FOUND (--dep is unavailable)"),
            }
            println!("deps cache: {}", rustcheck::deps_cache_dir().display());

            let canary = check("pub fn canary() -> u8 { 0 }", &CheckOptions::default());
            println!(
                "canary: {} ({} ms, sandbox: {})",
                canary.status(),
                canary.duration_ms.round(),
                canary.sandbox
            );

            if canary.success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}
