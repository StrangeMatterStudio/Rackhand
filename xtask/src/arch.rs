//! `cargo xtask arch-check`: the dependency rules from design 7.2.
//!
//! - Policy crates (Detect, Runbook model) depend on nothing of ours.
//! - Hub systems never depend on Web.
//! - Incidents reaches Actions only through the `StartJob` command (it hears back through the Bus).
//! - No Node or interpreter in the server crates (design 5.2, D8).

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Crates that hold pure policy and may depend on no workspace crate.
const POLICY_CRATES: &[&str] = &["rackhand-detect", "rackhand-runbook"];
/// Programs a build script must never run.
const FORBIDDEN_PROGRAMS: &[&str] = &["node", "npm", "npx", "yarn", "pnpm", "python", "python3", "deno", "bun"];
/// The only item of `actions` that `incidents` may use.
const INCIDENTS_ACTIONS_ALLOWED: &[&str] = &["StartJob"];

#[derive(Debug, Default)]
pub struct Model {
    pub crates: Vec<CrateNode>,
    pub hub_refs: Vec<ModuleRef>,
    pub files: Vec<FileFact>,
}

#[derive(Debug)]
pub struct CrateNode {
    pub name: String,
    /// Workspace crates this crate depends on (normal and build dependencies).
    pub internal_deps: Vec<String>,
}

/// A reference from one hub module to another, found in `crates/rackhand-hub/src`.
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleRef {
    pub from: String,
    pub to: String,
    /// The first path segment after the target module, if any (`StartJob` in `crate::actions::StartJob`).
    pub item: Option<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Debug)]
pub enum FileFact {
    PackageJson(PathBuf),
    BuildScriptRuns { crate_name: String, program: String },
}

#[derive(Debug)]
pub struct Violation {
    pub rule: &'static str,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.rule, self.message)
    }
}

/// Applies every rule to the model.
pub fn check(model: &Model) -> Vec<Violation> {
    let mut violations = Vec::new();
    for node in &model.crates {
        if POLICY_CRATES.contains(&node.name.as_str()) {
            for dep in &node.internal_deps {
                violations.push(Violation {
                    rule: "policy-crate",
                    message: format!("policy crate `{}` depends on workspace crate `{dep}`", node.name),
                });
            }
        }
    }
    for r in &model.hub_refs {
        if r.to == "web" && r.from != "web" {
            violations.push(Violation {
                rule: "no-web",
                message: format!("hub module `{}` uses `web` ({}:{})", r.from, r.file, r.line),
            });
        }
        if r.from == "incidents" && r.to == "actions" {
            let allowed = r
                .item
                .as_deref()
                .is_some_and(|item| INCIDENTS_ACTIONS_ALLOWED.contains(&item));
            if !allowed {
                let what = r.item.as_deref().unwrap_or("the module itself");
                violations.push(Violation {
                    rule: "incidents-actions",
                    message: format!(
                        "`incidents` uses `actions::{what}` ({}:{}); only `actions::StartJob` is allowed",
                        r.file, r.line
                    ),
                });
            }
        }
    }
    for fact in &model.files {
        match fact {
            FileFact::PackageJson(path) => violations.push(Violation {
                rule: "no-node",
                message: format!("`{}` brings a Node toolchain into the server crates", path.display()),
            }),
            FileFact::BuildScriptRuns { crate_name, program } => violations.push(Violation {
                rule: "no-interpreter",
                message: format!("the build script of `{crate_name}` runs `{program}`"),
            }),
        }
    }
    violations
}

/// Finds references to other hub modules in one source file of hub module `module`.
///
/// Recognizes `crate::<module>` paths anywhere (including `use crate::{a, b::C}` groups) and, in a module's own
/// `mod.rs`, `super::<module>` paths.
pub fn scan_hub_source(module: &str, file: &str, src: &str) -> Vec<ModuleRef> {
    let mut refs = Vec::new();
    let is_mod_root = file.ends_with("mod.rs") && file.matches('/').count() <= 1;
    for (idx, raw_line) in src.lines().enumerate() {
        let line = strip_line_comment(raw_line);
        let mut prefixes = vec!["crate::"];
        if is_mod_root {
            prefixes.push("super::");
        }
        for prefix in prefixes {
            let mut rest = line;
            while let Some(pos) = find_path_start(rest, prefix) {
                let after = &rest[pos + prefix.len()..];
                for (to, item) in paths_after(after) {
                    if to != module && to != "self" && to != "super" {
                        refs.push(ModuleRef {
                            from: module.to_string(),
                            to,
                            item,
                            file: file.to_string(),
                            line: idx + 1,
                        });
                    }
                }
                rest = after;
            }
        }
    }
    refs
}

fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(pos) => &line[..pos],
        None => line,
    }
}

/// Finds `prefix` where it starts a path (not inside a longer identifier such as `mycrate::`).
fn find_path_start(haystack: &str, prefix: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(prefix) {
        let pos = from + rel;
        let before = haystack[..pos].chars().next_back();
        if before.is_none_or(|c| !(c.is_alphanumeric() || c == '_')) {
            return Some(pos);
        }
        from = pos + prefix.len();
    }
    None
}

/// Parses what follows `crate::`: either `module::Item...` or a `{...}` group of such paths.
fn paths_after(after: &str) -> Vec<(String, Option<String>)> {
    if let Some(group) = after.strip_prefix('{') {
        let end = matching_brace(group).unwrap_or(group.len());
        return split_top_level(&group[..end])
            .iter()
            .flat_map(|p| single_path(p.trim()))
            .collect();
    }
    single_path(after)
}

/// Parses `module`, `module::Item...` or `module::{A, B}` into one entry per item.
fn single_path(path: &str) -> Vec<(String, Option<String>)> {
    let Some(module) = ident_prefix(path) else {
        return Vec::new();
    };
    let rest = &path[module.len()..];
    match rest.strip_prefix("::") {
        Some(group) if group.starts_with('{') => {
            let inner = &group[1..];
            let end = matching_brace(inner).unwrap_or(inner.len());
            split_top_level(&inner[..end])
                .iter()
                .map(|item| (module.to_string(), ident_prefix(item.trim()).map(str::to_string)))
                .collect()
        }
        Some(r) => vec![(module.to_string(), ident_prefix(r).map(str::to_string))],
        None => vec![(module.to_string(), None)],
    }
}

fn ident_prefix(s: &str) -> Option<&str> {
    let end = s.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(s.len());
    (end > 0).then(|| &s[..end])
}

fn matching_brace(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(i),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Splits a `use` group on top-level commas, expanding nested `module::{A, B}` into `module::A`, `module::B`.
fn split_top_level(group: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for c in group.chars() {
        match c {
            '{' => {
                depth += 1;
                current.push(c);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    let mut expanded = Vec::new();
    for part in parts {
        let part = part.trim().to_string();
        if part.is_empty() {
            continue;
        }
        match part.find("::{") {
            Some(pos) => {
                let head = &part[..pos];
                let inner = part[pos + 3..].trim_end_matches('}');
                for item in split_top_level(inner) {
                    expanded.push(format!("{head}::{item}"));
                }
            }
            None => expanded.push(part),
        }
    }
    expanded
}

/// Returns the forbidden programs a build script starts with `Command::new("...")`.
pub fn build_script_programs(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = script;
    while let Some(pos) = rest.find("Command::new(") {
        let after = rest[pos + "Command::new(".len()..].trim_start();
        if let Some(quoted) = after.strip_prefix('"') {
            if let Some(end) = quoted.find('"') {
                let program = &quoted[..end];
                let base = program.rsplit('/').next().unwrap_or(program);
                if FORBIDDEN_PROGRAMS.contains(&base) {
                    found.push(base.to_string());
                }
            }
        }
        rest = after;
    }
    found
}

/// Builds the model from `cargo metadata` and the workspace sources.
pub fn load(root: &Path) -> Result<Model> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout).context("parsing cargo metadata")?;
    let packages = meta["packages"].as_array().context("cargo metadata has no packages")?;
    let names: Vec<String> = packages
        .iter()
        .filter_map(|p| p["name"].as_str().map(str::to_string))
        .collect();

    let mut model = Model::default();
    for package in packages {
        let name = package["name"].as_str().unwrap_or_default().to_string();
        let internal_deps = package["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|d| d["kind"].as_str() != Some("dev"))
            .filter_map(|d| d["name"].as_str())
            .filter(|d| names.iter().any(|n| n == d))
            .map(str::to_string)
            .collect();
        let manifest = PathBuf::from(package["manifest_path"].as_str().unwrap_or_default());
        let crate_dir = manifest.parent().map(Path::to_path_buf).unwrap_or_default();
        let build_rs = crate_dir.join("build.rs");
        if let Ok(script) = std::fs::read_to_string(&build_rs) {
            for program in build_script_programs(&script) {
                model.files.push(FileFact::BuildScriptRuns {
                    crate_name: name.clone(),
                    program,
                });
            }
        }
        model.crates.push(CrateNode { name, internal_deps });
    }

    for dir in [root.join("crates"), root.join("xtask")] {
        find_files(&dir, "package.json", &mut |path| {
            model.files.push(FileFact::PackageJson(path))
        })?;
    }

    let hub_src = root.join("crates/rackhand-hub/src");
    if hub_src.is_dir() {
        for entry in std::fs::read_dir(&hub_src)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let module = entry.file_name().to_string_lossy().to_string();
            let mut files = Vec::new();
            find_files(&entry.path(), ".rs", &mut |p| files.push(p))?;
            for file in files {
                let src = std::fs::read_to_string(&file)?;
                let rel = file
                    .strip_prefix(&hub_src)
                    .unwrap_or(&file)
                    .to_string_lossy()
                    .replace('\\', "/");
                model.hub_refs.extend(scan_hub_source(&module, &rel, &src));
            }
        }
    }
    Ok(model)
}

/// Calls `found` for every file under `dir` whose name ends with `suffix`, skipping `target` and `node_modules`.
fn find_files(dir: &Path, suffix: &str, found: &mut dyn FnMut(PathBuf)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.file_type()?.is_dir() {
            if name != "target" && name != "node_modules" && !name.starts_with('.') {
                find_files(&path, suffix, found)?;
            }
        } else if name.ends_with(suffix) {
            found(path);
        }
    }
    Ok(())
}

/// `cargo xtask arch-check`.
pub fn run(root: &Path) -> Result<()> {
    let violations = check(&load(root)?);
    if violations.is_empty() {
        println!("no violations");
        Ok(())
    } else {
        for v in &violations {
            println!("{v}");
        }
        bail!("{} dependency-rule violation(s)", violations.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_node(name: &str, deps: &[&str]) -> CrateNode {
        CrateNode {
            name: name.to_string(),
            internal_deps: deps.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn policy_crate_with_internal_dependency_is_reported() {
        let model = Model {
            crates: vec![
                crate_node("rackhand-detect", &["rackhand-store"]),
                crate_node("rackhand-store", &[]),
            ],
            ..Model::default()
        };
        let violations = check(&model);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].message.contains("rackhand-detect"));
        assert!(violations[0].message.contains("rackhand-store"));
    }

    #[test]
    fn hub_module_using_web_is_reported() {
        let refs = scan_hub_source("incidents", "incidents/mod.rs", "use crate::web::pages;\n");
        let model = Model {
            hub_refs: refs,
            ..Model::default()
        };
        let violations = check(&model);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].message.contains("web"));
    }

    #[test]
    fn incidents_calling_actions_beyond_start_job_is_reported() {
        let bad = scan_hub_source(
            "incidents",
            "incidents/route.rs",
            "use crate::actions::{StartJob, Executor};\nfn f() { crate::actions::cancel(); }\n",
        );
        let violations = check(&Model {
            hub_refs: bad,
            ..Model::default()
        });
        assert_eq!(violations.len(), 2, "{violations:?}");

        let good = scan_hub_source("incidents", "incidents/route.rs", "use crate::actions::StartJob;\n");
        assert!(
            check(&Model {
                hub_refs: good,
                ..Model::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn clean_workspace_has_no_violations() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let model = load(&root).unwrap();
        assert!(model.crates.iter().any(|c| c.name == "rackhand-hub"));
        let violations = check(&model);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn no_node_or_interpreter_in_server_crates() {
        let model = Model {
            files: vec![
                FileFact::PackageJson("crates/rackhand-hub/web/package.json".into()),
                FileFact::BuildScriptRuns {
                    crate_name: "rackhand-hub".into(),
                    program: "node".into(),
                },
            ],
            ..Model::default()
        };
        assert_eq!(check(&model).len(), 2);

        let script = "fn main() { std::process::Command::new(\"python3\").arg(\"gen.py\"); }";
        assert_eq!(build_script_programs(script), vec!["python3".to_string()]);
        assert!(build_script_programs("fn main() { println!(\"cargo:rerun-if-changed=x\"); }").is_empty());
    }
}
