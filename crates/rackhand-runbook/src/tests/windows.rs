//! The Windows scripts the dispatcher runs (7.3.7, 7.8.3, T90) against what the hub sends: every diagnostic has a script and a
//! schema of the same parameters and patterns, so the dispatcher refuses what the hub would have refused, and the patch
//! runbook's arguments are what its schema takes.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::{builtin, diagnostics};

#[derive(Deserialize)]
struct Schema {
    script: String,
    params: BTreeMap<String, Param>,
}

#[derive(Deserialize)]
struct Param {
    #[serde(rename = "type")]
    kind: String,
    pattern: String,
}

fn windows_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows")
}

fn schema(script: &str) -> Schema {
    let path = windows_dir().join("schemas").join(format!("{script}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn type_name(t: crate::params::ParamType) -> &'static str {
    match t {
        crate::params::ParamType::Int => "int",
        crate::params::ParamType::Bool => "bool",
        _ => "string",
    }
}

#[test]
fn every_diagnostic_has_a_windows_script_and_a_schema_of_its_own_limits() {
    for d in diagnostics::builtin() {
        let script = d.windows_script();
        assert!(windows_dir().join("scripts").join(format!("{script}.ps1")).is_file(), "{script}: no script");
        let s = schema(&script);
        assert_eq!(s.script, script);
        assert_eq!(
            s.params.keys().collect::<Vec<_>>(),
            d.params.keys().collect::<Vec<_>>(),
            "{script}: its parameters"
        );
        for (name, p) in &d.params {
            let theirs = &s.params[name];
            assert_eq!(theirs.pattern, p.pattern, "{script}/{name}: the same pattern as the hub's");
            assert_eq!(theirs.kind, type_name(p.kind), "{script}/{name}: the same type");
        }
    }
}

#[test]
fn the_shipped_scripts_and_schemas_are_the_same_set() {
    let names = |dir: &str, ext: &str| {
        let mut names: Vec<String> = std::fs::read_dir(windows_dir().join(dir))
            .unwrap()
            .filter_map(|e| {
                let p = e.ok()?.path();
                (p.extension()?.to_str()? == ext).then(|| p.file_stem()?.to_str().map(String::from))?
            })
            .collect();
        names.sort();
        names
    };
    assert_eq!(names("scripts", "ps1"), names("schemas", "json"));
}

#[test]
fn patch_windows_arguments_are_what_its_script_takes() {
    let s = schema("patch-windows");
    assert_eq!(s.params.keys().collect::<Vec<_>>(), ["phase"]);
    let re = regex::Regex::new(&format!("^(?:{})$", s.params["phase"].pattern)).unwrap();
    let rb = crate::runbook::Runbook::parse(builtin::runbook("patch-windows").unwrap()).unwrap();
    for step in rb.steps.iter().filter(|s| s.windows_script.is_some()) {
        assert_eq!(step.windows_script.as_deref(), Some("patch-windows"));
        let args = step.windows_args.as_ref().unwrap();
        assert_eq!(args.keys().collect::<Vec<_>>(), ["phase"], "{}", step.id);
        assert!(re.is_match(&args["phase"]), "{}: `{}` is a phase the script takes", step.id, args["phase"]);
    }
}
