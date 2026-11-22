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
        let incidents = Incidents::new(db.clone(), ingest, Bus::new());
        let (library, _) = Library::new(db.clone(), crate::audit::Audit::new(db.writer()));
        let starts = Arc::new(Starts::default());
        let routing = Routing::new(incidents.clone(), starts.clone());
        Env { db, incidents, library, starts, routing }
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
