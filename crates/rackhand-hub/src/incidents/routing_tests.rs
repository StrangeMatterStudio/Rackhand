use std::sync::{Arc, Mutex};

use rackhand_detect::rules::Severity;
use rackhand_runbook::runbook::Runbook;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::super::Incidents;
use super::super::lifecycle::Opening;
use super::{JobStarter, MachineFacts, Routing, choose};
use crate::actions::StartJob;
use crate::bus::{Bus, JobOutcome};
use crate::ingest::Ingest;
use crate::library::items::{Kind, Library};

const M1: &str = "01JD0000000000000000000001";
const T0: i64 = 1_795_068_000_000;
const MIN: i64 = 60_000;
const KIND: &str = "service.not_active";

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

/// Records the jobs routing asks for.
#[derive(Debug, Default)]
struct Starts(Mutex<Vec<StartJob>>);

impl JobStarter for Starts {
    fn start(&self, job: StartJob) -> super::BoxFuture<Result<(), String>> {
        self.0.lock().unwrap().push(job);
        Box::pin(async { Ok(()) })
    }
}

impl Starts {
    fn taken(&self) -> Vec<StartJob> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

#[derive(Debug)]
struct Roomy;
impl crate::ingest::DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

struct Env {
    db: Arc<Db>,
    incidents: Incidents,
    library: Library,
    starts: Arc<Starts>,
    routing: Routing,
}

/// A runbook for `service.not_active` at `autonomy`, with `targets` as TOML (empty: a general one).
fn runbook(name: &str, autonomy: u8, targets: &str) -> String {
    let targets = if targets.is_empty() { String::new() } else { format!("targets = {targets}\n") };
    format!(
        "name = \"{name}\"\ndescription = \"test\"\n{targets}identity = \"automation\"\nrisk = \"low\"\nautonomy = {autonomy}\n\
         triggers = {{ incident_kinds = [\"{KIND}\"], auto = true }}\n[[step]]\nid = \"tell\"\nkind = \"notify\"\nmessage = \"restarting\"\n"
    )
}

impl Env {
    async fn new(name: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("rackhand-routing-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let rows = vec![
            RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
            RowWrite::insert(
                "machines",
                Row::from([
                    ("id", t(M1)),
                    ("site_id", t("s1")),
                    ("name", t("web")),
                    ("kind", t("linux")),
                    ("tags", t("[\"web\"]")),
                    ("state", t("enrolled")),
                ]),
            ),
        ];
        db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
        let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
        ingest.start(0).await.unwrap();
        let incidents = Incidents::new(db.clone(), ingest, Bus::new());
        let (library, _) = Library::new(db.clone(), crate::audit::Audit::new(db.writer()));
        let starts = Arc::new(Starts::default());
        let routing = Routing::new(incidents.clone(), starts.clone());
        Env { db, incidents, library, starts, routing }
    }

    /// `config/hub.toml` (7.8.1).
    async fn settings(&self, text: &str) {
        crate::library::config::put(&self.db, crate::library::config::HUB, text, "admin", T0).await.unwrap();
    }

    fn approval_expires_at(&self) -> i64 {
        self.db.readers().with(|c| c.query_row("SELECT expires_at FROM approvals", [], |r| r.get(0))).unwrap()
    }

    async fn save(&self, name: &str, autonomy: u8, targets: &str) {
        self.library.save(Kind::Runbook, name, &runbook(name, autonomy, targets), "admin", T0).await.unwrap();
    }

    /// Opens (or reopens) the incident for nginx on M1 and routes it.
    async fn open(&self, now: i64) -> String {
        let o = Opening {
            machine_id: Some(M1.into()),
            rule_id: None,
            dedupe_key: format!("{M1}:{KIND}:nginx.service"),
            kind: KIND.into(),
            severity: Severity::Warning,
            title: "nginx.service not active".into(),
        };
        let inc = self.incidents.open(o, now).await.unwrap().unwrap();
        self.routing.route(&inc.id, now).await.unwrap();
        inc.id
    }

    fn state(&self, id: &str) -> String {
        self.db
            .readers()
            .with(|c| c.query_row("SELECT state FROM incidents WHERE id = ?1", [id], |r| r.get(0)))
            .unwrap()
    }

    fn notes(&self, id: &str) -> Vec<String> {
        self.db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT json_extract(data, '$.text') FROM incident_events
                     WHERE incident_id = ?1 AND kind = 'note' ORDER BY at_ms, rowid",
                )?;
                s.query_map([id], |r| r.get(0))?.collect()
            })
            .unwrap()
    }

    /// The job Actions would have recorded for `start`, ended with `outcome`; then its `JobFinished`.
    async fn finish(&self, start: &StartJob, job: &str, outcome: JobOutcome, now: i64) {
        let incident = start.incident_id.as_deref();
        self.finish_job(job, &start.name, &start.machine_id, &start.requested_by, incident, outcome, now).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_job(
        &self,
        job: &str,
        name: &str,
        machine: &str,
        requested_by: &str,
        incident: Option<&str>,
        outcome: JobOutcome,
        now: i64,
    ) {
        let state = match outcome {
            JobOutcome::Succeeded => "succeeded",
            JobOutcome::TimedOut => "timed_out",
            _ => "failed",
        };
        let row = Row::from([
            ("id", t(job)),
            ("kind", t("runbook")),
            ("name", t(name)),
            ("target", t(machine)),
            ("requested_by", t(requested_by)),
            ("incident_id", incident.map(t).unwrap_or(Value::Null)),
            ("state", t(state)),
        ]);
        self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row)])).await.unwrap();
        self.routing.job_finished(job, outcome, now).await.unwrap();
    }

    async fn resolve(&self, id: &str, now: i64) {
        self.incidents.resolve_by(id, "rule", now).await.unwrap();
    }
}

fn facts(name: &str, kind: &str, tags: &[&str], roles: &[&str]) -> MachineFacts {
    MachineFacts {
        name: name.into(),
        kind: kind.into(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        roles: roles.iter().map(|s| s.to_string()).collect(),
    }
}

fn parsed(name: &str, targets: &str) -> Runbook {
    Runbook::parse(&runbook(name, 2, targets)).unwrap()
}

mod routing {
    use super::*;

    /// Machine, then one of its tags (or roles), then its kind, then a general runbook; ties to the name that sorts
    /// first; a runbook whose targets leave the machine out isn't a candidate (7.5.2).
    #[test]
    fn most_specific_runbook_wins_ties_by_name() {
        let web = facts("web", "linux", &["web"], &["storage"]);
        let all = [
            parsed("general-b", ""),
            parsed("general-a", ""),
            parsed("by-kind", "{ kinds = [\"linux\"] }"),
            parsed("by-tag", "{ tags = [\"web\"] }"),
            parsed("by-role", "{ roles = [\"storage\"] }"),
            parsed("by-machine", "{ machines = [\"web\"] }"),
            parsed("other-machine", "{ machines = [\"nas\"] }"),
            parsed("windows-only", "{ kinds = [\"windows\"] }"),
        ];
        let pick = |names: &[&str], m: &MachineFacts| {
            let set: Vec<Runbook> = all.iter().filter(|r| names.contains(&r.name.as_str())).cloned().collect();
            choose(&set, KIND, m).map(|r| r.name.clone())
        };
        let every: Vec<&str> = all.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(pick(&every, &web).as_deref(), Some("by-machine"));
        assert_eq!(pick(&["general-a", "by-kind", "by-tag", "other-machine"], &web).as_deref(), Some("by-tag"));
        assert_eq!(pick(&["by-role", "by-tag"], &web).as_deref(), Some("by-role"), "a tie at tags: by name");
        assert_eq!(pick(&["general-b", "by-kind"], &web).as_deref(), Some("by-kind"));
        assert_eq!(pick(&["general-b", "general-a"], &web).as_deref(), Some("general-a"), "ties by name");
        assert_eq!(pick(&["other-machine", "windows-only"], &web), None, "targets that leave the machine out");
        // only automatic triggers for the incident's kind
        let other_kind = Runbook::parse(&runbook("x", 2, "").replace(KIND, "disk.full")).unwrap();
        assert_eq!(choose(&[other_kind], KIND, &web), None);
        let manual = Runbook::parse(&runbook("y", 2, "").replace("auto = true", "auto = false")).unwrap();
        assert_eq!(choose(&[manual], KIND, &web), None, "auto = false is for people only");
    }

    /// Level 0 tells (7.6.8): nothing runs; a person gets the incident with a note naming the runbook.
    #[tokio::test(flavor = "multi_thread")]
    async fn level_0_tells_a_person_without_running() {
        let env = Env::new("level0").await;
        env.save("nginx-restart", 0, "").await;
        let id = env.open(T0).await;
        assert_eq!(env.state(&id), "human");
        assert!(env.starts.taken().is_empty(), "nothing ran");
        let notes = env.notes(&id);
        assert!(notes.iter().any(|n| n.contains("nginx-restart") && n.contains("level 0")), "{notes:?}");
    }

    /// Level 1 proposes (7.6.8): an approval for exactly this run; the job starts with it once a person approves.
    #[tokio::test(flavor = "multi_thread")]
    async fn level_1_creates_approval_and_waits() {
        let env = Env::new("level1").await;
        env.save("nginx-restart", 1, "").await;
        let id = env.open(T0).await;
        assert_eq!(env.state(&id), "automation");
        assert!(env.starts.taken().is_empty(), "waits for the approval");
        let (approval, requester, tool, state): (String, String, String, String) = env
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT id, requested_by, tool, state FROM approvals", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
            })
            .unwrap();
        assert_eq!(
            (requester.as_str(), tool.as_str(), state.as_str()),
            (format!("incident:{id}").as_str(), "run_runbook", "pending")
        );
        let decider = crate::policy::approvals::Decider {
            user: "admin".into(),
            role: crate::policy::approvals::Role::Admin,
            step_up_fresh: true,
        };
        crate::policy::approvals::Approvals::new(env.db.clone())
            .decide(&approval, &decider, true, T0 + MIN)
            .await
            .unwrap();
        env.routing.approval_decided(&approval, true, T0 + MIN).await.unwrap();
        let started = env.starts.taken();
        assert_eq!(started.len(), 1, "{started:?}");
        assert_eq!(started[0].approval_id.as_deref(), Some(approval.as_str()));
        assert_eq!(started[0].incident_id.as_deref(), Some(id.as_str()));
        assert_eq!((started[0].name.as_str(), started[0].machine_id.as_str()), ("nginx-restart", M1));
        // a rejection hands it to a person
        let env = Env::new("level1-rejected").await;
        env.save("nginx-restart", 1, "").await;
        let id = env.open(T0).await;
        let approval: String =
            env.db.readers().with(|c| c.query_row("SELECT id FROM approvals", [], |r| r.get(0))).unwrap();
        env.routing.approval_decided(&approval, false, T0 + MIN).await.unwrap();
        assert_eq!(env.state(&id), "human");
        assert!(env.starts.taken().is_empty());
    }

    /// A succeeded job isn't the end (7.5.2, E57): the incident waits 10 minutes for its condition to clear, then goes
    /// on as if the job had failed. One whose condition cleared in time stays resolved.
    #[tokio::test(flavor = "multi_thread")]
    async fn success_waits_for_clear_then_failed_after_10_min() {
        let env = Env::new("success-wait").await;
        env.save("nginx-restart", 2, "").await;
        let id = env.open(T0).await;
        assert_eq!(env.state(&id), "automation");
        let start = env.starts.taken().pop().expect("started at level 2");
        assert_eq!(start.requested_by, format!("incident:{id}"));
        env.finish(&start, "01JOB0000000000000000000A1", JobOutcome::Succeeded, T0 + MIN).await;
        env.routing.tick(T0 + 10 * MIN).await.unwrap();
        assert_eq!(env.state(&id), "automation", "still within the 10 minutes");
        env.routing.tick(T0 + 11 * MIN + 1).await.unwrap();
        assert_eq!(env.state(&id), "human", "the condition persisted");
        assert!(
            env.notes(&id).iter().any(|n| n.contains("persists") && n.contains("nginx-restart")),
            "{:?}",
            env.notes(&id)
        );
        // cleared in time: left resolved
        let env = Env::new("success-clear").await;
        env.save("nginx-restart", 2, "").await;
        let id = env.open(T0).await;
        let start = env.starts.taken().pop().unwrap();
        env.finish(&start, "01JOB0000000000000000000A2", JobOutcome::Succeeded, T0 + MIN).await;
        env.resolve(&id, T0 + 2 * MIN).await;
        env.routing.tick(T0 + 20 * MIN).await.unwrap();
        assert_eq!(env.state(&id), "resolved");
    }

    /// The wait is the `[incidents] clear_wait_min` setting (7.8.1), and the note says how long it was.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_clear_wait_follows_the_setting() {
        let env = Env::new("clear-setting").await;
        env.settings("[incidents]\nclear_wait_min = 2\n").await;
        env.save("nginx-restart", 2, "").await;
        let id = env.open(T0).await;
        let start = env.starts.taken().pop().unwrap();
        env.finish(&start, "01JOB0000000000000000000A4", JobOutcome::Succeeded, T0 + MIN).await;
        env.routing.tick(T0 + 2 * MIN).await.unwrap();
        assert_eq!(env.state(&id), "automation", "within the 2 minutes");
        env.routing.tick(T0 + 3 * MIN).await.unwrap();
        assert_eq!(env.state(&id), "human", "the condition persisted 2 minutes");
        assert!(env.notes(&id).iter().any(|n| n.contains("persists 2 minutes")), "{:?}", env.notes(&id));
    }

    /// An approval routing asks for expires after 24 hours by default, else after `[approvals] expiry_h` (7.8.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_routing_approval_expires_at_the_setting() {
        let env = Env::new("expiry-default").await;
        env.save("nginx-restart", 1, "").await;
        env.open(T0).await;
        assert_eq!(env.approval_expires_at(), T0 + 24 * 60 * MIN);
        let env = Env::new("expiry-setting").await;
        env.settings("[approvals]\nexpiry_h = 2\n").await;
        env.save("nginx-restart", 1, "").await;
        env.open(T0).await;
        assert_eq!(env.approval_expires_at(), T0 + 2 * 60 * MIN);
    }

    /// A failed job goes to a person (no playbooks until T78), with the reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_job_goes_to_a_person() {
        let env = Env::new("failed").await;
        env.save("nginx-restart", 2, "").await;
        let id = env.open(T0).await;
        let start = env.starts.taken().pop().unwrap();
        env.finish(&start, "01JOB0000000000000000000A3", JobOutcome::Failed, T0 + MIN).await;
        assert_eq!(env.state(&id), "human");
        assert!(
            env.notes(&id).iter().any(|n| n.contains("nginx-restart") && n.contains("failed")),
            "{:?}",
            env.notes(&id)
        );
        // nothing matching: a person, at once
        let env = Env::new("nothing").await;
        let id = env.open(T0).await;
        assert_eq!(env.state(&id), "human");
    }
}

mod attempts {
    use super::*;

    /// At most 2 automatic starts per incident in 24 hours (E56, AC64): the third reopen goes to a person with the note.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_automatic_starts_per_24h_then_human() {
        let env = Env::new("limit").await;
        env.save("nginx-restart", 2, "").await;
        for n in 0..2 {
            let at = T0 + n * 20 * MIN;
            let id = env.open(at).await;
            let start = env.starts.taken().pop().unwrap_or_else(|| panic!("start {}", n + 1));
            env.finish(&start, &format!("01JOB000000000000000000B{n}"), JobOutcome::Failed, at + MIN).await;
            env.resolve(&id, at + 2 * MIN).await;
        }
        let id = env.open(T0 + 40 * MIN).await;
        assert!(env.starts.taken().is_empty(), "no third start");
        assert_eq!(env.state(&id), "human");
        assert!(env.notes(&id).iter().any(|n| n.contains("attempt limit reached")), "{:?}", env.notes(&id));
    }

    /// The limit is the `[incidents] runbook_starts_24h` setting (7.8.1), and the note names it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_starts_limit_follows_the_setting() {
        let env = Env::new("limit-setting").await;
        env.settings("[incidents]\nrunbook_starts_24h = 3\n").await;
        env.save("nginx-restart", 2, "").await;
        for n in 0..3 {
            let at = T0 + n * 20 * MIN;
            let id = env.open(at).await;
            let start = env.starts.taken().pop().unwrap_or_else(|| panic!("start {}", n + 1));
            env.finish(&start, &format!("01JOB000000000000000000E{n}"), JobOutcome::Failed, at + MIN).await;
            env.resolve(&id, at + 2 * MIN).await;
        }
        let id = env.open(T0 + 60 * MIN).await;
        assert!(env.starts.taken().is_empty(), "no fourth start");
        assert!(env.notes(&id).iter().any(|n| n.contains("started 3 times")), "{:?}", env.notes(&id));
    }

    /// A job a person starts from the dashboard isn't counted (7.5.2).
    #[tokio::test(flavor = "multi_thread")]
    async fn person_started_jobs_not_counted() {
        let env = Env::new("person").await;
        env.save("nginx-restart", 2, "").await;
        let id = env.open(T0).await;
        let start = env.starts.taken().pop().unwrap();
        env.finish(&start, "01JOB0000000000000000000C1", JobOutcome::Failed, T0 + MIN).await;
        // a person tries it from the dashboard; their job ends too
        let by_person = StartJob { requested_by: "user:admin".into(), ..start.clone() };
        env.finish(&by_person, "01JOB0000000000000000000C2", JobOutcome::Failed, T0 + 3 * MIN).await;
        assert_eq!(env.state(&id), "human", "a person's job doesn't route the incident");
        env.resolve(&id, T0 + 4 * MIN).await;
        env.open(T0 + 10 * MIN).await;
        assert_eq!(env.starts.taken().len(), 1, "the second automatic start: the person's job didn't count");
    }

    /// Reopening keeps the history, so the count runs across reopens and over 24 hours, not per opening.
    #[tokio::test(flavor = "multi_thread")]
    async fn limits_count_across_reopens() {
        let env = Env::new("reopens").await;
        env.save("nginx-restart", 2, "").await;
        let mut ids = Vec::new();
        for n in 0..2 {
            let at = T0 + n * 20 * MIN;
            let id = env.open(at).await;
            let start = env.starts.taken().pop().unwrap();
            env.finish(&start, &format!("01JOB000000000000000000D{n}"), JobOutcome::Failed, at + MIN).await;
            env.resolve(&id, at + 2 * MIN).await;
            ids.push(id);
        }
        assert_eq!(ids[0], ids[1], "a reopen is the same incident");
        // a day after the first start, one start is allowed again
        let day = 24 * 60 * MIN;
        env.open(T0 + day + MIN).await;
        assert_eq!(env.starts.taken().len(), 1, "the first start is outside the 24 hours");
    }
}

/// E55: a job whose detached step is still running when it times out opens an incident on its machine.
#[tokio::test(flavor = "multi_thread")]
async fn timed_out_detached_step_opens_incident() {
    let env = Env::new("timed-out").await;
    let job = "01JOB0000000000000000000E1";
    env.finish_job(job, "patch", M1, "schedule:patch_window", None, JobOutcome::TimedOut, T0).await;
    let (kind, machine, state): (String, String, String) = env
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT kind, machine_id, state FROM incidents", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        })
        .unwrap();
    assert_eq!((kind.as_str(), machine.as_str()), ("job.timed_out", M1));
    assert_ne!(state, "resolved");
}

/// 7.5.3 step 6: a patch job that didn't succeed opens `patch_failed` on its machine, once while it is open, whoever
/// asked for it; the machine's next patch job that succeeds resolves it. Other jobs, and one a person cancelled, don't.
#[tokio::test(flavor = "multi_thread")]
async fn failed_patch_opens_patch_failed_and_a_success_resolves_it() {
    let env = Env::new("patch-failed").await;
    let incidents = || -> Vec<(String, String, String)> {
        env.db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT kind, machine_id, state FROM incidents ORDER BY opened_at")?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap()
    };
    env.finish_job("01JOB0000000000000000000F1", "restart-web", M1, "user:admin", None, JobOutcome::Failed, T0).await;
    env.finish_job("01JOB0000000000000000000F2", "patch-debian", M1, "user:admin", None, JobOutcome::Cancelled, T0)
        .await;
    assert!(incidents().is_empty(), "{:?}", incidents());
    env.finish_job("01JOB0000000000000000000F3", "patch-debian", M1, "schedule:patch", None, JobOutcome::Failed, T0)
        .await;
    env.finish_job(
        "01JOB0000000000000000000F4",
        "patch-debian",
        M1,
        "schedule:patch",
        None,
        JobOutcome::Failed,
        T0 + MIN,
    )
    .await;
    let open = incidents();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!((open[0].0.as_str(), open[0].1.as_str()), ("patch_failed", M1));
    assert_ne!(open[0].2, "resolved");
    let at = T0 + 2 * MIN;
    env.finish_job("01JOB0000000000000000000F5", "patch-debian", M1, "schedule:patch", None, JobOutcome::Succeeded, at)
        .await;
    assert_eq!(incidents()[0].2, "resolved");
}

/// Quarantine from a finding (7.5.6, 7.8.2, D18, D57, D61, D80, AC17, AC18, AC58): an enabled automatic rule starts it without an
/// approval; otherwise a critical finding proposes it for an approval with step-up, as the machine's policy allows.
mod quarantine {
    use super::*;
    use crate::policy::approvals::{Approvals, Decider, Role};
    use crate::policy::quarantine::{Rule, Severity as RuleSeverity, put_rule};

    const KIND: &str = "conn.known_bad";

    fn rule() -> Rule {
        Rule {
            id: "r1".into(),
            name: "dmz known bad".into(),
            severity_at_least: RuleSeverity::Critical,
            event_kinds: vec![KIND.into()],
            match_tags: vec!["dmz".into()],
            match_roles: vec![],
            enabled: true,
            enabled_by: None,
            enabled_at: None,
        }
    }

    impl Env {
        async fn machine(&self, set: &[(&'static str, Value)]) {
            let set: Row = set.iter().cloned().collect();
            let update = rackhand_store::RowUpdate { table: "machines", key: ("id", t(M1)), set };
            let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
            self.db.writer().send(WriteCmd::RegistryChange(change)).await.unwrap();
        }

        async fn policy(&self, quarantine: &str) {
            let policy = Row::from([("id", t("p1")), ("name", t("guests")), ("quarantine", t(quarantine))]);
            self.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("policies", policy)])).await.unwrap();
            self.machine(&[("policy_id", t("p1"))]).await;
        }

        async fn rule(&self) {
            put_rule(&self.db, &rule(), "admin", true, T0).await.unwrap();
        }

        /// A finding of `kind` at `severity` on M1, routed.
        async fn finding(&self, kind: &str, severity: Severity, now: i64) -> String {
            self.finding_on(M1, kind, severity, now).await
        }

        async fn finding_on(&self, machine: &str, kind: &str, severity: Severity, now: i64) -> String {
            let o = Opening {
                machine_id: Some(machine.into()),
                rule_id: None,
                dedupe_key: format!("{machine}:{kind}:203.0.113.9"),
                kind: kind.into(),
                severity,
                title: format!("{kind} 203.0.113.9"),
            };
            let inc = self.incidents.open(o, now).await.unwrap().unwrap();
            self.routing.route(&inc.id, now).await.unwrap();
            inc.id
        }

        fn quarantine_state(&self) -> String {
            self.db
                .readers()
                .with(|c| c.query_row("SELECT quarantine FROM machines WHERE id = ?1", [M1], |r| r.get(0)))
                .unwrap()
        }

        fn approvals(&self) -> Vec<(String, String, i64, String, String)> {
            self.db
                .readers()
                .with(|c| {
                    let mut s = c.prepare(
                        "SELECT id, json_extract(args, '$.name'), step_up, risk, requested_by FROM approvals ORDER BY id",
                    )?;
                    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
                })
                .unwrap()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn auto_rule_matches_tag_quarantines_without_approval() {
        let env = Env::new("q-auto").await;
        env.machine(&[("tags", t("[\"dmz\",\"web\"]"))]).await;
        env.rule().await;
        let id = env.finding(KIND, Severity::Critical, T0).await;
        let starts = env.starts.taken();
        assert_eq!(starts.len(), 1, "{starts:?}");
        assert_eq!((starts[0].name.as_str(), starts[0].requested_by.as_str()), ("quarantine", "rule:r1"));
        assert_eq!((starts[0].machine_id.as_str(), starts[0].approval_id.as_deref()), (M1, None));
        assert_eq!(starts[0].incident_id.as_deref(), Some(id.as_str()));
        assert!(env.approvals().is_empty(), "no approval is asked for");
        assert_eq!(env.state(&id), "automation");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hypervisor_with_same_finding_not_quarantined() {
        let env = Env::new("q-hyp").await;
        env.machine(&[("tags", t("[\"dmz\"]")), ("roles", t("[\"hypervisor\"]"))]).await;
        env.rule().await;
        env.policy("approval").await;
        let id = env.finding(KIND, Severity::Critical, T0).await;
        assert!(env.starts.taken().is_empty());
        assert!(env.approvals().is_empty(), "not even proposed: the incident is all there is");
        assert_eq!((env.quarantine_state().as_str(), env.state(&id).as_str()), ("none", "human"));
        assert!(env.notes(&id).iter().any(|n| n.contains("never quarantined")), "{:?}", env.notes(&id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_critical_finding_proposes_quarantine_for_an_approval_with_step_up() {
        let env = Env::new("q-propose").await;
        env.policy("approval").await;
        let id = env.finding(KIND, Severity::Critical, T0).await;
        assert!(env.starts.taken().is_empty(), "nothing starts without the approval");
        let approvals = env.approvals();
        assert_eq!(approvals.len(), 1, "{approvals:?}");
        let (approval, name, step_up, risk, by) = approvals[0].clone();
        assert_eq!((name.as_str(), step_up, risk.as_str()), ("quarantine", 1, "high"));
        assert_eq!(by, format!("incident:{id}"));
        assert_eq!(env.quarantine_state(), "pending");
        // approved with step-up: the job starts with that approval
        let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
        Approvals::new(env.db.clone()).decide(&approval, &admin, true, T0 + MIN).await.unwrap();
        env.routing.approval_decided(&approval, true, T0 + MIN).await.unwrap();
        let starts = env.starts.taken();
        assert_eq!(starts.len(), 1, "{starts:?}");
        assert_eq!(
            (starts[0].name.as_str(), starts[0].approval_id.as_deref()),
            ("quarantine", Some(approval.as_str()))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rejected_proposal_clears_pending_and_goes_to_a_person() {
        let env = Env::new("q-reject").await;
        let id = env.finding(KIND, Severity::Critical, T0).await;
        let approval = env.approvals()[0].0.clone();
        assert_eq!(env.quarantine_state(), "pending");
        let admin = Decider { user: "admin".into(), role: Role::Admin, step_up_fresh: true };
        Approvals::new(env.db.clone()).decide(&approval, &admin, false, T0 + MIN).await.unwrap();
        env.routing.approval_decided(&approval, false, T0 + MIN).await.unwrap();
        assert_eq!(env.quarantine_state(), "none");
        assert_eq!(env.state(&id), "human");
        assert!(env.starts.taken().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_proposal_clears_pending() {
        let env = Env::new("q-expire").await;
        env.finding(KIND, Severity::Critical, T0).await;
        assert_eq!(env.quarantine_state(), "pending");
        // the approval expiry of 7.8.1: 24 hours by default
        env.routing.tick(T0 + 23 * 60 * MIN).await.unwrap();
        assert_eq!(env.quarantine_state(), "pending", "still within the 24 hours it can be approved");
        env.routing.tick(T0 + 24 * 60 * MIN + MIN).await.unwrap();
        assert_eq!(env.quarantine_state(), "none");
        // and `[approvals] expiry_h` when set
        let env = Env::new("q-expire-setting").await;
        env.settings("[approvals]\nexpiry_h = 1\n").await;
        env.finding(KIND, Severity::Critical, T0).await;
        env.routing.tick(T0 + 61 * MIN).await.unwrap();
        assert_eq!(env.quarantine_state(), "none", "an hour, as set");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lesser_findings_and_other_kinds_are_not_proposed() {
        let env = Env::new("q-lesser").await;
        env.finding(KIND, Severity::Warning, T0).await;
        env.finding("service.not_active", Severity::Critical, T0).await;
        assert!(env.approvals().is_empty());
        assert_eq!(env.quarantine_state(), "none");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn policy_never_means_never_even_with_a_matching_rule() {
        let env = Env::new("q-never").await;
        env.machine(&[("tags", t("[\"dmz\"]"))]).await;
        env.rule().await;
        env.policy("never").await;
        let id = env.finding(KIND, Severity::Critical, T0).await;
        assert!(env.starts.taken().is_empty() && env.approvals().is_empty());
        assert_eq!(env.state(&id), "human");
        assert!(env.notes(&id).iter().any(|n| n.contains("policy")), "{:?}", env.notes(&id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn auto_rule_matching_monitor_machine_asks_for_an_approval_instead() {
        let env = Env::new("q-monitor").await;
        const M2: &str = "01JD0000000000000000000002";
        let guest = Row::from([
            ("id", t(M2)),
            ("site_id", t("s1")),
            ("name", t("guest")),
            ("kind", t("linux")),
            ("access", t("monitor")),
            ("tags", t("[\"dmz\"]")),
            ("state", t("enrolled")),
        ]);
        env.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("machines", guest)])).await.unwrap();
        env.rule().await;
        env.finding_on(M2, KIND, Severity::Critical, T0).await;
        assert!(env.starts.taken().is_empty(), "no automatic policy applies to a monitor machine");
        assert_eq!(env.approvals().len(), 1);
        let state: String = env
            .db
            .readers()
            .with(|c| c.query_row("SELECT quarantine FROM machines WHERE id = ?1", [M2], |r| r.get(0)))
            .unwrap();
        assert_eq!(state, "pending");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_mode_and_appliance_stay_with_a_person() {
        for (name, set) in [("q-remote", ("mode", t("remote"))), ("q-appliance", ("kind", t("appliance")))] {
            let env = Env::new(name).await;
            env.machine(&[("tags", t("[\"dmz\"]")), set]).await;
            env.rule().await;
            env.policy("approval").await;
            let id = env.finding(KIND, Severity::Critical, T0).await;
            assert!(env.starts.taken().is_empty() && env.approvals().is_empty(), "{name}");
            assert_eq!(env.state(&id), "human", "{name}");
            assert!(env.notes(&id).iter().any(|n| n.contains("can't be quarantined")), "{name}: {:?}", env.notes(&id));
        }
    }
}

/// Routing to playbooks (7.5.2, 7.5.4, D76, D96, E15, E21).
mod playbook_routing {
    use super::*;
    use crate::incidents::routing::playbook_routing::{AssistStarter, PlaybookRequest, PlaybookStart};

    /// Records what routing asks the assistant for, and answers as told.
    #[derive(Debug)]
    struct Assist {
        asked: Mutex<Vec<PlaybookRequest>>,
        answer: Mutex<PlaybookStart>,
    }

    impl AssistStarter for Assist {
        fn start(&self, req: PlaybookRequest) -> super::super::BoxFuture<PlaybookStart> {
            self.asked.lock().unwrap().push(req);
            let answer = self.answer.lock().unwrap().clone();
            Box::pin(async move { answer })
        }
    }

    fn playbook(name: &str, kinds: &str, autonomy: u8) -> String {
        format!(
            "+++\nname = \"{name}\"\nincident_kinds = [{kinds}]\nautonomy = {autonomy}\nrisk = \"normal\"\ntools = [\"get_incident\", \"finish_job\"]\nhosts = \"incident\"\nmax_runtime = \"20m\"\n+++\n## When\nIt is down.\n## Read first\nThe incident.\n## Do\nLook.\n## Done when\nFixed.\n## Stop and ask if\nUnsure.\n"
        )
    }

    struct Pb {
        env: Env,
        assist: Arc<Assist>,
    }

    async fn pb(name: &str) -> Pb {
        let mut env = Env::new(name).await;
        let assist = Arc::new(Assist {
            asked: Mutex::new(Vec::new()),
            answer: Mutex::new(PlaybookStart::Accepted { job_id: "01JASSISTJOB0000000000000A".into() }),
        });
        env.routing = env.routing.clone().with_assist(assist.clone());
        Pb { env, assist }
    }

    impl Pb {
        async fn book(&self, name: &str, kinds: &str, autonomy: u8) {
            self.env.library.save(Kind::Playbook, name, &playbook(name, kinds, autonomy), "admin", T0).await.unwrap();
        }

        fn asked(&self) -> Vec<PlaybookRequest> {
            std::mem::take(&mut *self.assist.asked.lock().unwrap())
        }

        async fn open(&self, kind: &str, severity: Severity, now: i64) -> String {
            let o = Opening {
                machine_id: Some(M1.into()),
                rule_id: None,
                dedupe_key: format!("{M1}:{kind}:x"),
                kind: kind.into(),
                severity,
                title: format!("{kind} on web"),
            };
            let inc = self.env.incidents.open(o, now).await.unwrap().unwrap();
            self.env.routing.route(&inc.id, now).await.unwrap();
            inc.id
        }

        fn events(&self, id: &str, kind: &str) -> i64 {
            self.env
                .db
                .readers()
                .with(|c| {
                    c.query_row(
                        "SELECT count(*) FROM incident_events WHERE incident_id = ?1 AND kind = ?2",
                        [id, kind],
                        |r| r.get(0),
                    )
                })
                .unwrap()
        }

        /// An assistant job for the incident that ended as `outcome` with `reason`, and its `JobFinished`.
        async fn assistant_ends(&self, incident: &str, playbook: &str, outcome: JobOutcome, reason: &str, now: i64) {
            let state = if outcome == JobOutcome::Succeeded { "succeeded" } else { "failed" };
            let row = Row::from([
                ("id", t("01JASSISTJOB0000000000000A")),
                ("kind", t("assistant")),
                ("name", t(playbook)),
                ("requested_by", t("incidents")),
                ("incident_id", t(incident)),
                ("state", t(state)),
                ("outcome", t(reason)),
            ]);
            self.env.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row)])).await.unwrap();
            self.env.routing.job_finished("01JASSISTJOB0000000000000A", outcome, now).await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_playbook_takes_an_incident_no_runbook_does_with_a_brief_and_its_hosts() {
        let p = pb("pb-takes").await;
        p.book("service-down", "\"service.not_active\"", 1).await;
        let id = p.open(KIND, Severity::Warning, T0).await;
        let asked = p.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        let req = &asked[0];
        assert_eq!(
            (req.playbook.as_str(), req.incident_id.as_str(), req.hosts.as_slice()),
            ("service-down", id.as_str(), &[M1.to_string()][..])
        );
        assert_eq!(req.deadline_ms, T0 + 20 * MIN, "the playbook's `max_runtime`");
        for part in ["## The rule", "## Incident", "## This job", "autonomy level: 1", "untrusted_output"] {
            assert!(req.brief.contains(part), "{part}: {}", req.brief);
        }
        assert_eq!(p.env.state(&id), "assistant");
        assert_eq!(p.events(&id, "assistant.started"), 1);
        // a kind no playbook is for goes to a person, as it did before playbooks
        let other = p.open("cpu.busy", Severity::Warning, T0).await;
        assert!(p.asked().is_empty());
        assert_eq!(p.env.state(&other), "human");
    }

    /// `[incidents] assistant_jobs_24h` allows more assistant jobs per incident, and a playbook with no `max_runtime`
    /// gets the `[assistant] deadline_min` setting (7.8.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn assistant_jobs_per_incident_and_the_deadline_follow_the_settings() {
        let p = pb("pb-settings").await;
        p.env.settings("[incidents]\nassistant_jobs_24h = 2\n\n[assistant]\ndeadline_min = 45\n").await;
        let book = playbook("service-down", "\"service.not_active\"", 1).replace("max_runtime = \"20m\"\n", "");
        p.env.library.save(Kind::Playbook, "service-down", &book, "admin", T0).await.unwrap();
        let id = p.open(KIND, Severity::Warning, T0).await;
        let asked = p.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].deadline_ms, T0 + 45 * MIN, "the setting, for a playbook that sets no runtime");
        p.env.resolve(&id, T0 + 5 * MIN).await;
        p.open(KIND, Severity::Warning, T0 + 30 * MIN).await;
        assert_eq!(p.asked().len(), 1, "a second assistant job within the day");
        p.env.resolve(&id, T0 + 35 * MIN).await;
        p.open(KIND, Severity::Warning, T0 + 60 * MIN).await;
        assert!(p.asked().is_empty(), "no third");
        assert!(p.env.notes(&id).iter().any(|n| n.contains("attempt limit reached")), "{:?}", p.env.notes(&id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_assistant_job_per_incident_per_24h() {
        let p = pb("pb-limit").await;
        p.book("service-down", "\"service.not_active\"", 1).await;
        let id = p.open(KIND, Severity::Warning, T0).await;
        assert_eq!(p.asked().len(), 1);
        p.env.resolve(&id, T0 + 5 * MIN).await;
        // the same incident again within the day: the second goes to a person with the note
        let again = p.open(KIND, Severity::Warning, T0 + 30 * MIN).await;
        assert_eq!(again, id, "a reopen is the same incident");
        assert!(p.asked().is_empty(), "no second assistant job");
        assert_eq!(p.env.state(&id), "human");
        assert!(p.env.notes(&id).iter().any(|n| n.contains("attempt limit reached")), "{:?}", p.env.notes(&id));
        // a day after the first, one is allowed again
        p.env.resolve(&id, T0 + 40 * MIN).await;
        p.open(KIND, Severity::Warning, T0 + 24 * 60 * MIN + MIN).await;
        assert_eq!(p.asked().len(), 1, "the first start is outside the 24 hours");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_step_names_the_playbook_and_kinds_are_skipped() {
        let p = pb("pb-onfail").await;
        p.book("service-down", "\"service.not_active\"", 1).await;
        p.book("careful", "", 1).await;
        let runbook = "name = \"nginx-restart\"\ndescription = \"t\"\nidentity = \"automation\"\nrisk = \"low\"\nautonomy = 2\n\
             triggers = { incident_kinds = [\"service.not_active\"], auto = true }\n[[step]]\nid = \"restart\"\nkind = \"ssh\"\n\
             cmd = [\"sudo\", \"/usr/local/lib/rackhand/run\", \"/usr/bin/systemctl\", \"restart\", \"nginx.service\"]\n\
             on_failure = { playbook = \"careful\" }\n";
        p.env.library.save(Kind::Runbook, "nginx-restart", runbook, "admin", T0).await.unwrap();
        let id = p.open(KIND, Severity::Warning, T0).await;
        let start = p.env.starts.taken().pop().expect("the runbook starts first");
        assert_eq!(start.name, "nginx-restart");
        assert!(p.asked().is_empty(), "a runbook is tried before a playbook");
        // it fails at its step
        let job = "01JJOB0000000000000000000F";
        let step = Row::from([
            ("job_id", t(job)),
            ("step_id", t("restart")),
            ("state", t("failed")),
            ("started_at", Value::Integer(T0)),
        ]);
        let row = Row::from([
            ("id", t(job)),
            ("kind", t("runbook")),
            ("name", t("nginx-restart")),
            ("target", t(M1)),
            ("requested_by", t(&format!("incident:{id}"))),
            ("incident_id", t(&id)),
            ("state", t("failed")),
        ]);
        p.env
            .db
            .writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert("jobs", row), RowWrite::insert("job_steps", step)]))
            .await
            .unwrap();
        p.env.routing.job_finished(job, JobOutcome::Failed, T0 + MIN).await.unwrap();
        let asked = p.asked();
        assert_eq!(
            asked.iter().map(|r| r.playbook.as_str()).collect::<Vec<_>>(),
            ["careful"],
            "the named one, not the kind's"
        );
        assert_eq!(p.env.state(&id), "assistant");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_operator_or_declines_go_human_with_callout() {
        for reason in ["no_operator", "declined"] {
            let p = pb(&format!("pb-{reason}")).await;
            p.book("service-down", "\"service.not_active\"", 1).await;
            *p.assist.answer.lock().unwrap() = PlaybookStart::ToPerson { reason: reason.into() };
            let id = p.open(KIND, Severity::Warning, T0).await;
            assert_eq!(p.env.state(&id), "human", "{reason}");
            assert!(p.env.notes(&id).iter().any(|n| n.contains("operator")), "{reason}: {:?}", p.env.notes(&id));
            let callouts: i64 = p
                .env
                .db
                .readers()
                .with(|c| {
                    c.query_row(
                        "SELECT count(*) FROM incident_events WHERE incident_id = ?1 AND kind = 'human' AND json_extract(data, '$.callout') = 1",
                        [&id],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(callouts, 1, "{reason}: a callout says so");
            // the job's own end arrives too, and changes nothing more
            p.assistant_ends(&id, "service-down", JobOutcome::Failed, reason, T0 + MIN).await;
            assert_eq!(p.events(&id, "human"), 1, "{reason}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn level_0_tells_a_person_what_would_run() {
        let p = pb("pb-level0").await;
        p.book("service-down", "\"service.not_active\"", 0).await;
        let id = p.open(KIND, Severity::Warning, T0).await;
        assert!(p.asked().is_empty());
        assert_eq!(p.env.state(&id), "human");
        assert!(p.env.notes(&id).iter().any(|n| n.contains("level 0")), "{:?}", p.env.notes(&id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn assistant_resolves_event_incident_only_level_2_3_warning() {
        // (autonomy, severity) -> the incident after the assistant says resolved
        for (n, (level, severity, resolved)) in [
            (1u8, Severity::Warning, false),
            (2, Severity::Warning, true),
            (2, Severity::Critical, false),
            (3, Severity::Critical, false),
        ]
        .into_iter()
        .enumerate()
        {
            let p = pb(&format!("pb-event{n}")).await;
            p.book("security-finding", "\"auth.keys_changed\"", level).await;
            let id = p.open("auth.keys_changed", severity, T0).await;
            assert_eq!(p.asked().len(), 1, "an assistant looks at it at any level");
            p.assistant_ends(&id, "security-finding", JobOutcome::Succeeded, "resolved", T0 + 5 * MIN).await;
            let state = p.env.state(&id);
            assert_eq!(state == "resolved", resolved, "level {level}, {severity:?}: {state}");
            if !resolved {
                assert_eq!(state, "human", "a person closes it");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_condition_incident_waits_for_the_condition_after_resolved_then_goes_to_a_person() {
        let p = pb("pb-wait").await;
        p.book("service-down", "\"service.not_active\"", 1).await;
        let id = p.open(KIND, Severity::Warning, T0).await;
        p.assistant_ends(&id, "service-down", JobOutcome::Succeeded, "resolved", T0 + 5 * MIN).await;
        assert_eq!(p.env.state(&id), "assistant", "waiting to see the condition clear");
        p.env.routing.tick(T0 + 10 * MIN).await.unwrap();
        assert_eq!(p.env.state(&id), "assistant", "not yet");
        p.env.routing.tick(T0 + 16 * MIN).await.unwrap();
        assert_eq!(p.env.state(&id), "human");
        assert!(
            p.env.notes(&id).iter().any(|n| n.contains("persists 10 minutes after the assistant")),
            "{:?}",
            p.env.notes(&id)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_assistant_that_hands_over_or_runs_out_of_time_goes_to_a_person() {
        for (n, reason) in ["needs_human", "timed_out", "failed"].iter().enumerate() {
            let p = pb(&format!("pb-end{n}")).await;
            p.book("service-down", "\"service.not_active\"", 1).await;
            let id = p.open(KIND, Severity::Warning, T0).await;
            p.assistant_ends(&id, "service-down", JobOutcome::Failed, reason, T0 + 5 * MIN).await;
            assert_eq!(p.env.state(&id), "human", "{reason}");
        }
    }
}
