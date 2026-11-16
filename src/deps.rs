//! Resolve the crates a snippet depends on, so `rustc` can type-check code
//! that uses `serde`, `tokio` or anything else from the registry.
//!
//! `rustc` alone cannot: a snippet with `use serde_json::json;` fails with
//! `E0433` unless the caller passes `--extern serde_json=/path/lib....rlib`,
//! plus `-L dependency=<dir>` for the transitive crates. Building those rlibs
//! is Cargo's job, so this module creates a throwaway project inside the user's
//! cache directory, builds it once, and remembers where the artifacts landed.
//! Later runs only read that manifest (a few hundred microseconds), so the
//! compiler stays the only slow step.
//!
//! Only registry crates with a version requirement are supported. Path and git
//! dependencies would have to be bound into the sandbox as well, and silently
//! reaching outside the isolated filesystem is not something this tool does.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One `--dep` argument, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepSpec {
    /// Crate name as published on crates.io, e.g. `serde-json`.
    pub name: String,
    /// Version requirement; `*` when the user did not give one.
    pub req: String,
}

impl DepSpec {
    /// Parse `name`, `name@1.2` or `name=1.2`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("empty dependency spec".to_string());
        }
        let (name, req) = match spec.find(['@', '=']) {
            Some(i) => (&spec[..i], &spec[i + 1..]),
            None => (spec, "*"),
        };
        let name = name.trim();
        let req = req.trim();

        let valid = !name.is_empty()
            && name
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid {
            return Err(format!("invalid crate name in {spec:?}"));
        }
        if req.is_empty() {
            return Err(format!("empty version requirement for {name}"));
        }
        if req.starts_with("path:") || req.starts_with("git:") {
            return Err(format!(
                "{name}: only registry crates are supported, {req:?} is not"
            ));
        }
        Ok(Self { name: name.to_string(), req: req.to_string() })
    }

    /// Name as spelled in Rust source: `serde-json` becomes `serde_json`.
    pub fn extern_name(&self) -> String {
        self.name.replace('-', "_")
    }
}

/// Where the artifacts of a resolved dependency set live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEnv {
    /// Directories to pass as `-L dependency=<dir>`.
    pub lib_dirs: Vec<PathBuf>,
    /// `(extern name, artifact path)` for every crate the user asked for.
    pub externs: Vec<(String, PathBuf)>,
    /// The scratch project, kept for diagnostics.
    pub cache_dir: PathBuf,
    /// True when this run had to invoke Cargo.
    #[serde(default)]
    pub fresh_build: bool,
}

/// Root of the dependency cache, overridable with `RUSTCHECK_CACHE_DIR`.
pub fn cache_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("RUSTCHECK_CACHE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("rustcheck");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".cache").join("rustcheck");
        }
    }
    std::env::temp_dir().join("rustcheck-cache")
}

/// Parse and resolve `--dep` specs, returning the externs to hand to `rustc`.
///
/// The error is a `(error code, message)` pair: `E_BAD_DEP` for a spec that
/// cannot be parsed, `E_NO_CARGO` when Cargo is missing, `E_DEPS` when the
/// build failed (no network, unknown crate, version mismatch).
pub fn resolve_specs(raw: &[String], edition: &str) -> Result<DepEnv, (&'static str, String)> {
    let mut specs = Vec::with_capacity(raw.len());
    for spec in raw {
        specs.push(DepSpec::parse(spec).map_err(|e| ("E_BAD_DEP", e))?);
    }
    resolve(&specs, edition)
}

/// Resolve already-parsed specs, building the scratch project on a cache miss.
pub fn resolve(specs: &[DepSpec], edition: &str) -> Result<DepEnv, (&'static str, String)> {
    if specs.is_empty() {
        return Ok(DepEnv {
            lib_dirs: Vec::new(),
            externs: Vec::new(),
            cache_dir: PathBuf::new(),
            fresh_build: false,
        });
    }

    let dir = cache_root().join(cache_key(specs, edition));
    if let Some(env) = load_cached(&dir) {
        return Ok(env);
    }
    build(&dir, specs, edition).map_err(|e| ("E_DEPS", e))?;
    match load_cached(&dir) {
        Some(env) => Ok(env),
        // A successful build without a usable manifest means the artifacts
        // vanished between the build and the read; say so instead of guessing.
        None => Err((
            "E_DEPS",
            format!("dependency build left no usable artifacts in {}", dir.display()),
        )),
    }
}

/// Read a previously written manifest, if every artifact behind it still exists.
fn load_cached(dir: &Path) -> Option<DepEnv> {
    let raw = std::fs::read_to_string(dir.join("externs.json")).ok()?;
    let mut env: DepEnv = serde_json::from_str(&raw).ok()?;
    let intact = env.externs.iter().all(|(_, path)| path.exists())
        && env.lib_dirs.iter().all(|path| path.exists())
        && !env.externs.is_empty();
    if !intact {
        return None;
    }
    env.fresh_build = false;
    Some(env)
}

/// Create the scratch project and build it, then record where the rlibs are.
fn build(dir: &Path, specs: &[DepSpec], _edition: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir.join("src"))
        .map_err(|e| format!("cannot create cache directory {}: {e}", dir.display()))?;

    let mut manifest = String::from(
        "[package]\nname = \"rustcheck-deps\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    );
    for spec in specs {
        manifest.push_str(&format!("{} = \"{}\"\n", spec.name, spec.req));
    }
    std::fs::write(dir.join("Cargo.toml"), manifest)
        .map_err(|e| format!("cannot write scratch manifest: {e}"))?;
    let lib_rs = dir.join("src").join("lib.rs");
    if !lib_rs.exists() {
        std::fs::write(&lib_rs, "// scratch target for rustcheck; intentionally empty\n")
            .map_err(|e| format!("cannot write scratch source: {e}"))?;
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("--message-format=json")
        .current_dir(dir)
        .output()
        .map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    "cargo not found in PATH; external crates need Cargo to fetch and build them"
                        .to_string()
                }
                _ => format!("cannot run cargo: {e}"),
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr
            .lines()
            .filter(|l| !l.trim().is_empty())
            .rev()
            .take(6)
            .collect();
        let detail = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        return Err(if detail.is_empty() {
            format!("cargo build failed with {}", output.status)
        } else {
            format!("cargo build failed:\n{detail}")
        });
    }

    let artifacts = parse_artifacts(&String::from_utf8_lossy(&output.stdout));
    let mut externs = Vec::with_capacity(specs.len());
    let mut lib_dirs: Vec<PathBuf> = Vec::new();

    for spec in specs {
        let wanted = spec.extern_name();
        match artifacts.get(&wanted) {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    if !lib_dirs.iter().any(|d| d == parent) {
                        lib_dirs.push(parent.to_path_buf());
                    }
                }
                externs.push((wanted, path.clone()));
            }
            None => {
                return Err(format!(
                    "cargo built the scratch project but produced no library artifact for {}; \
                     transitive-only crates cannot be passed at the top level",
                    spec.name
                ))
            }
        }
    }

    let env = DepEnv { lib_dirs, externs, cache_dir: dir.to_path_buf(), fresh_build: true };
    let tmp = dir.join("externs.json.tmp");
    let body = serde_json::to_vec_pretty(&env)
        .map_err(|e| format!("cannot serialize dependency manifest: {e}"))?;
    std::fs::write(&tmp, body).map_err(|e| format!("cannot write dependency manifest: {e}"))?;
    std::fs::rename(&tmp, dir.join("externs.json"))
        .map_err(|e| format!("cannot store dependency manifest: {e}"))?;
    Ok(())
}

/// Map normalized crate name to its compiled artifact, from Cargo's JSON stream.
fn parse_artifacts(stdout: &str) -> BTreeMap<String, PathBuf> {
    let mut map = BTreeMap::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let Some(name) = value
            .get("target")
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
        else {
            continue;
        };
        let Some(files) = value.get("filenames").and_then(|f| f.as_array()) else {
            continue;
        };
        let artifact = files.iter().filter_map(|f| f.as_str()).find(|f| {
            let lower = f.to_ascii_lowercase();
            lower.ends_with(".rlib") || lower.ends_with(".so") || lower.ends_with(".dylib")
        });
        if let Some(path) = artifact {
            map.insert(name.replace('-', "_"), PathBuf::from(path));
        }
    }
    map
}

/// Stable-enough cache key: the dependency set, the edition and the toolchain.
fn cache_key(specs: &[DepSpec], edition: &str) -> String {
    let mut entries: Vec<String> = specs
        .iter()
        .map(|s| format!("{}={}", s.name, s.req))
        .collect();
    entries.sort();

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entries.hash(&mut hasher);
    edition.hash(&mut hasher);
    rustc_version().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// First line of `rustc -vV`, so a toolchain upgrade invalidates cached rlibs.
fn rustc_version() -> String {
    Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_name_with_any_version() {
        let spec = DepSpec::parse("serde").unwrap();
        assert_eq!(spec.name, "serde");
        assert_eq!(spec.req, "*");
        assert_eq!(spec.extern_name(), "serde");
    }

    #[test]
    fn parses_version_and_normalises_extern_name() {
        let spec = DepSpec::parse("serde-json@1.0").unwrap();
        assert_eq!(spec.name, "serde-json");
        assert_eq!(spec.req, "1.0");
        assert_eq!(spec.extern_name(), "serde_json");
        assert_eq!(DepSpec::parse("tokio=1").unwrap().req, "1");
    }

    #[test]
    fn rejects_path_and_git_dependencies() {
        assert!(DepSpec::parse("mylib=path:../mylib").is_err());
        assert!(DepSpec::parse("mylib=git:https://example.com/x").is_err());
    }

    #[test]
    fn rejects_junk_names() {
        assert!(DepSpec::parse("").is_err());
        assert!(DepSpec::parse("9lives").is_err());
        assert!(DepSpec::parse("bad name").is_err());
        assert!(DepSpec::parse("serde@").is_err());
    }

    #[test]
    fn reads_artifacts_from_cargo_json() {
        let stream = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"serde_json","kind":["lib"]},"filenames":["/tmp/libserde_json-abc.rlib","/tmp/libserde_json-abc.rmeta"]}"#,
            "\n",
            r#"{"reason":"build-script-executed","target":{"name":"whatever"}}"#,
            "\n"
        );
        let map = parse_artifacts(stream);
        assert_eq!(
            map.get("serde_json").map(|p| p.to_string_lossy().to_string()),
            Some("/tmp/libserde_json-abc.rlib".to_string())
        );
    }

    #[test]
    fn empty_spec_list_resolves_to_nothing() {
        let env = resolve(&[], "2021").unwrap();
        assert!(env.externs.is_empty());
        assert!(env.lib_dirs.is_empty());
    }
}
