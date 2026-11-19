//! `cargo xtask ci-guard`: proves which events may reach the self-hosted runners (design 13, D37, AC44).
//!
//! Every job in `ci.yml` must carry the fork guard and its runner variable; every job in `ci-github-hosted.yml` must
//! run only when `RACKHAND_GITHUB_HOSTED` is `true`. The `if:` expressions are evaluated against the recorded event
//! payloads in `ci/fixtures/` with a small evaluator for exactly this expression grammar.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use yaml_rust2::{Yaml, YamlLoader};

use crate::workspace_root;

/// The fork guard every self-hosted job carries (design 13).
pub const GUARD: &str = "github.repository == 'StrangeMatterStudio/Rackhand' && (github.event_name == 'push' || \
github.event_name == 'workflow_dispatch' || github.event_name == 'schedule' || (github.event_name == 'pull_request' \
&& github.event.pull_request.head.repo.full_name == github.repository))";
/// The condition every job in the GitHub-hosted copy carries (D37).
pub const HOSTED: &str = "vars.RACKHAND_GITHUB_HOSTED == 'true'";
/// The nightly-only clause of the performance job.
pub const NIGHTLY: &str = "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')";
/// Runner label set to the repository variable that says such a runner exists (T04).
const LABEL_VARS: &[(&str, &str)] = &[
    ("sm-linux", "RACKHAND_CI_LINUX"),
    ("sm-linux-docker", "RACKHAND_CI_DOCKER"),
    ("sm-linux-kvm", "RACKHAND_CI_KVM"),
];

#[derive(Debug, Clone)]
pub struct Job {
    pub name: String,
    pub labels: Vec<String>,
    /// The `if:` expression without `${{ }}`; empty when the job has none.
    pub condition: String,
}

/// Repository variables (`vars.*`).
#[derive(Debug, Default, Clone)]
pub struct Vars(BTreeMap<String, String>);

impl Vars {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<const N: usize> From<[(&str, &str); N]> for Vars {
    fn from(items: [(&str, &str); N]) -> Self {
        Vars(items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }
}

/// The `github` context of one recorded event.
#[derive(Debug, Clone)]
pub struct Context(serde_json::Value);

impl Context {
    pub fn from_fixture(fixture: &serde_json::Value) -> Self {
        Context(fixture["github"].clone())
    }
}

pub fn load_fixture(name: &str) -> Result<serde_json::Value> {
    let path = workspace_root().join("ci/fixtures").join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn parse_workflow(text: &str) -> Result<Vec<Job>> {
    let docs = YamlLoader::load_from_str(text).context("parsing workflow YAML")?;
    let doc = docs.first().context("empty workflow")?;
    let Yaml::Hash(jobs) = &doc["jobs"] else {
        bail!("workflow has no jobs")
    };
    let mut out = Vec::new();
    for (name, job) in jobs {
        let name = name.as_str().context("job name")?.to_string();
        let labels = match &job["runs-on"] {
            Yaml::String(s) => vec![s.clone()],
            Yaml::Array(items) => items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        };
        let raw = match &job["if"] {
            Yaml::String(s) => s.trim().to_string(),
            Yaml::Boolean(b) => b.to_string(),
            _ => String::new(),
        };
        let condition = raw
            .strip_prefix("${{")
            .and_then(|s| s.strip_suffix("}}"))
            .map(|s| s.trim().to_string())
            .unwrap_or(raw);
        out.push(Job {
            name,
            labels,
            condition,
        });
    }
    Ok(out)
}

/// The condition a self-hosted job with `label` must have (`nightly` for the performance job).
pub fn expected_condition(label: &str, nightly: bool) -> Option<String> {
    let var = LABEL_VARS.iter().find(|(l, _)| *l == label)?.1;
    let mut expected = format!("({GUARD}) && vars.{var} == 'true'");
    if nightly {
        expected.push_str(&format!(" && {NIGHTLY}"));
    }
    Some(expected)
}

/// Reports every self-hosted job whose condition isn't exactly the guard plus its runner variable.
pub fn check_self_hosted_jobs(jobs: &[Job]) -> Vec<String> {
    let mut problems = Vec::new();
    for job in jobs {
        if !job.labels.iter().any(|l| l == "self-hosted") {
            problems.push(format!(
                "job `{}` in ci.yml doesn't run on self-hosted runners",
                job.name
            ));
            continue;
        }
        let label = job
            .labels
            .iter()
            .find(|l| l.starts_with("sm-"))
            .map(String::as_str)
            .unwrap_or("");
        match expected_condition(label, job.name == "perf") {
            Some(expected) if normalize(&job.condition) == normalize(&expected) => {}
            Some(_) => problems.push(format!(
                "job `{}` lacks the fork guard and its runner variable",
                job.name
            )),
            None => problems.push(format!(
                "job `{}` uses unknown runner labels {:?}",
                job.name, job.labels
            )),
        }
    }
    problems
}

pub fn check_hosted_jobs(jobs: &[Job]) -> Vec<String> {
    jobs.iter()
        .filter(|j| normalize(&j.condition) != normalize(HOSTED) || j.labels.iter().any(|l| l == "self-hosted"))
        .map(|j| format!("job `{}` in ci-github-hosted.yml must run only when {HOSTED}", j.name))
        .collect()
}

fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Str(String),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Str(s) => !s.is_empty(),
        }
    }

    fn loose_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Str(s)) | (Value::Str(s), Value::Null) => s.is_empty(),
            (a, b) => a == b,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    Eq,
    Ne,
    Str(String),
    Path(String),
}

fn tokenize(expr: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = expr.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            ' ' | '\n' | '\t' => i += 1,
            '(' => {
                tokens.push(Token::Open);
                i += 1;
            }
            ')' => {
                tokens.push(Token::Close);
                i += 1;
            }
            '&' if next == Some('&') => {
                tokens.push(Token::And);
                i += 2;
            }
            '|' if next == Some('|') => {
                tokens.push(Token::Or);
                i += 2;
            }
            '=' if next == Some('=') => {
                tokens.push(Token::Eq);
                i += 2;
            }
            '!' if next == Some('=') => {
                tokens.push(Token::Ne);
                i += 2;
            }
            '\'' => {
                let start = i + 1;
                let end = chars[start..]
                    .iter()
                    .position(|&ch| ch == '\'')
                    .context("unterminated string")?
                    + start;
                tokens.push(Token::Str(chars[start..end].iter().collect()));
                i = end + 1;
            }
            c if c.is_alphanumeric() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '.' | '-')) {
                    i += 1;
                }
                tokens.push(Token::Path(chars[start..i].iter().collect()));
            }
            other => bail!("unsupported character `{other}` in expression"),
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    ctx: &'a Context,
    vars: &'a Vars,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn or(&mut self) -> Result<Value> {
        let mut left = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.pos += 1;
            let right = self.and()?;
            left = Value::Bool(left.truthy() || right.truthy());
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Value> {
        let mut left = self.cmp()?;
        while self.peek() == Some(&Token::And) {
            self.pos += 1;
            let right = self.cmp()?;
            left = Value::Bool(left.truthy() && right.truthy());
        }
        Ok(left)
    }

    fn cmp(&mut self) -> Result<Value> {
        let left = self.primary()?;
        match self.peek() {
            Some(Token::Eq) => {
                self.pos += 1;
                let right = self.primary()?;
                Ok(Value::Bool(left.loose_eq(&right)))
            }
            Some(Token::Ne) => {
                self.pos += 1;
                let right = self.primary()?;
                Ok(Value::Bool(!left.loose_eq(&right)))
            }
            _ => Ok(left),
        }
    }

    fn primary(&mut self) -> Result<Value> {
        let token = self
            .tokens
            .get(self.pos)
            .cloned()
            .context("unexpected end of expression")?;
        self.pos += 1;
        match token {
            Token::Open => {
                let value = self.or()?;
                if self.tokens.get(self.pos) != Some(&Token::Close) {
                    bail!("missing `)`");
                }
                self.pos += 1;
                Ok(value)
            }
            Token::Str(s) => Ok(Value::Str(s)),
            Token::Path(p) => Ok(self.lookup(&p)),
            other => bail!("unexpected {other:?}"),
        }
    }

    fn lookup(&self, path: &str) -> Value {
        match path {
            "true" => return Value::Bool(true),
            "false" => return Value::Bool(false),
            _ => {}
        }
        if let Some(name) = path.strip_prefix("vars.") {
            return self
                .vars
                .0
                .get(name)
                .map(|v| Value::Str(v.clone()))
                .unwrap_or(Value::Null);
        }
        let Some(rest) = path.strip_prefix("github.") else {
            return Value::Null;
        };
        let mut node = &self.ctx.0;
        for part in rest.split('.') {
            node = &node[part];
        }
        match node {
            serde_json::Value::String(s) => Value::Str(s.clone()),
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Null => Value::Null,
            other => Value::Str(other.to_string()),
        }
    }
}

pub fn evaluate(expr: &str, ctx: &Context, vars: &Vars) -> Result<bool> {
    if expr.trim().is_empty() {
        return Ok(true);
    }
    let mut parser = Parser {
        tokens: tokenize(expr)?,
        pos: 0,
        ctx,
        vars,
    };
    let value = parser.or()?;
    if parser.pos != parser.tokens.len() {
        bail!("trailing tokens in `{expr}`");
    }
    Ok(value.truthy())
}

/// `cargo xtask ci-guard`.
pub fn run() -> Result<()> {
    let root = workspace_root();
    let ci = parse_workflow(&std::fs::read_to_string(root.join(".github/workflows/ci.yml"))?)?;
    let hosted = parse_workflow(&std::fs::read_to_string(
        root.join(".github/workflows/ci-github-hosted.yml"),
    )?)?;
    let mut problems = check_self_hosted_jobs(&ci);
    problems.extend(check_hosted_jobs(&hosted));

    let all = Vars::from([
        ("RACKHAND_CI_LINUX", "true"),
        ("RACKHAND_CI_DOCKER", "true"),
        ("RACKHAND_CI_KVM", "true"),
    ]);
    let mut names: Vec<String> = std::fs::read_dir(root.join("ci/fixtures"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .collect();
    names.sort();
    for name in &names {
        let fixture = load_fixture(name)?;
        let ctx = Context::from_fixture(&fixture);
        let expect = &fixture["expect"];
        for job in &ci {
            let key = if job.name == "perf" { "perf" } else { "self_hosted" };
            let want = expect[key].as_bool().with_context(|| format!("{name}: expect.{key}"))?;
            let got = evaluate(&job.condition, &ctx, &all)?;
            if got != want {
                problems.push(format!(
                    "{name}: ci.yml job `{}` gives {got}, expected {want}",
                    job.name
                ));
            }
        }
        for job in &hosted {
            let on = evaluate(&job.condition, &ctx, &Vars::from([("RACKHAND_GITHUB_HOSTED", "true")]))?;
            let off = evaluate(&job.condition, &ctx, &Vars::new())?;
            if !on || off {
                problems.push(format!(
                    "{name}: ci-github-hosted.yml job `{}` ignores RACKHAND_GITHUB_HOSTED",
                    job.name
                ));
            }
        }
        println!("{name}: as expected");
    }
    if problems.is_empty() {
        println!(
            "{} fixtures, {} self-hosted and {} hosted jobs checked",
            names.len(),
            ci.len(),
            hosted.len()
        );
        Ok(())
    } else {
        for p in &problems {
            println!("{p}");
        }
        bail!("{} workflow guard problem(s)", problems.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream_push() -> Context {
        Context::from_fixture(&load_fixture("push-upstream").unwrap())
    }

    fn all_vars() -> Vars {
        Vars::from([
            ("RACKHAND_CI_LINUX", "true"),
            ("RACKHAND_CI_DOCKER", "true"),
            ("RACKHAND_CI_KVM", "true"),
        ])
    }

    fn ci_jobs() -> Vec<Job> {
        let root = crate::workspace_root();
        parse_workflow(&std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap()).unwrap()
    }

    #[test]
    fn fork_pull_request_does_not_run_self_hosted() {
        let ctx = Context::from_fixture(&load_fixture("pr-from-fork").unwrap());
        for job in ci_jobs() {
            assert!(
                !evaluate(&job.condition, &ctx, &all_vars()).unwrap(),
                "job {} would run",
                job.name
            );
        }
    }

    #[test]
    fn upstream_push_and_same_repo_pr_run_self_hosted() {
        for fixture in ["push-upstream", "pr-same-repo"] {
            let ctx = Context::from_fixture(&load_fixture(fixture).unwrap());
            for job in ci_jobs().into_iter().filter(|j| j.name != "perf") {
                assert!(
                    evaluate(&job.condition, &ctx, &all_vars()).unwrap(),
                    "{fixture}: job {} skipped",
                    job.name
                );
            }
        }
    }

    #[test]
    fn push_in_a_fork_does_not_run_self_hosted() {
        let ctx = Context::from_fixture(&load_fixture("push-fork").unwrap());
        for job in ci_jobs() {
            assert!(
                !evaluate(&job.condition, &ctx, &all_vars()).unwrap(),
                "job {} would run",
                job.name
            );
        }
    }

    #[test]
    fn hosted_copy_runs_only_with_variable_true() {
        let root = crate::workspace_root();
        let hosted =
            parse_workflow(&std::fs::read_to_string(root.join(".github/workflows/ci-github-hosted.yml")).unwrap())
                .unwrap();
        assert!(!hosted.is_empty());
        let ctx = upstream_push();
        for job in &hosted {
            assert!(!evaluate(&job.condition, &ctx, &Vars::new()).unwrap());
            assert!(!evaluate(&job.condition, &ctx, &Vars::from([("RACKHAND_GITHUB_HOSTED", "false")])).unwrap());
            assert!(evaluate(&job.condition, &ctx, &Vars::from([("RACKHAND_GITHUB_HOSTED", "true")])).unwrap());
        }
    }

    #[test]
    fn job_without_guard_is_reported() {
        let workflow =
            "on: push\njobs:\n  sneaky:\n    runs-on: [self-hosted, sm-linux]\n    steps:\n      - run: echo hi\n";
        let jobs = parse_workflow(workflow).unwrap();
        let problems = check_self_hosted_jobs(&jobs);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("sneaky"));
    }

    #[test]
    fn jobs_skip_when_runner_variable_unset() {
        let ctx = upstream_push();
        let vars = Vars::from([("RACKHAND_CI_LINUX", "true"), ("RACKHAND_CI_DOCKER", "true")]);
        for job in ci_jobs() {
            let runs = evaluate(&job.condition, &ctx, &vars).unwrap();
            let kvm = job.labels.iter().any(|l| l == "sm-linux-kvm");
            assert_eq!(runs, !kvm && job.name != "perf", "job {}", job.name);
        }
    }
}
