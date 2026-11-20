use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::*;
use crate::bus::Bus;
use crate::ingest::{DiskSpace, Ingest};

const M1: &str = "01JD0000000000000000000001";
const M2: &str = "01JD0000000000000000000002";
const T0: i64 = 1_795_068_000_000;
const MIN: i64 = 60_000;
const HOUR: i64 = 3_600_000;

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

/// A transport that records what it was asked to send, failing while `fail` is set.
#[derive(Debug, Default)]
struct Fake {
    name: &'static str,
    sent: Mutex<Vec<Message>>,
    attempts: AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

impl Fake {
    fn new(name: &'static str) -> Arc<Fake> {
        Arc::new(Fake { name, ..Fake::default() })
    }
    fn sent(&self) -> Vec<Message> {
        self.sent.lock().unwrap().clone()
    }
}

impl Transport for Fake {
    fn name(&self) -> &str {
        self.name
    }
    fn send<'a>(&'a self, msg: &'a Message) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                return Err(SendError::Failed("connection refused".into()));
            }
            self.sent.lock().unwrap().push(msg.clone());
            Ok(())
        })
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

struct Env {
    db: Arc<Db>,
    notify: Notify,
    path: std::path::PathBuf,
}

async fn env(name: &str, transports: Vec<Arc<dyn Transport>>) -> Env {
    let dir = std::env::temp_dir().join(format!("rackhand-notify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let db = Arc::new(Db::open(&path).unwrap());
    let rows = vec![
        RowWrite::insert("sites", Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))])),
        RowWrite::insert("sites", Row::from([("id", t("s2")), ("name", t("cabin")), ("timezone", t("UTC"))])),
        RowWrite::insert(
            "machines",
            Row::from([("id", t(M1)), ("site_id", t("s1")), ("name", t("web")), ("kind", t("linux"))]),
        ),
        RowWrite::insert(
            "machines",
            Row::from([("id", t(M2)), ("site_id", t("s1")), ("name", t("nas")), ("kind", t("linux"))]),
        ),
    ];
    db.writer().send(WriteCmd::Batch(rows)).await.unwrap();
    let ingest = Ingest::new(db.clone(), Bus::new(), Arc::new(Roomy));
    let notify = Notify::new(db.clone(), ingest, transports).with_dashboard_url("https://hub.example.net");
    Env { db, notify, path }
}

impl Env {
    /// An incident row and one of its events, as Incidents writes them.
    /// `row` is the incident's (severity, state); `event` its (kind, data).
    async fn incident(&self, id: &str, machine: &str, row: (&str, &str), event: (&str, &str), at: i64) {
        let ((severity, state), (event, data)) = (row, event);
        let inc = Row::from([
            ("id", t(id)),
            ("machine_id", t(machine)),
            ("dedupe_key", t(&format!("{machine}:{id}"))),
            ("kind", t("disk.used")),
            ("severity", t(severity)),
            ("state", t(state)),
            ("title", t(&format!("disk.used_pct over 85 ({id})"))),
            ("opened_at", Value::Integer(T0)),
        ]);
        let ev = Row::from([
            ("id", t(&rackhand_store::ids::new_id().to_string())),
            ("incident_id", t(id)),
            ("at_ms", Value::Integer(at)),
            ("kind", t(event)),
            ("data", t(data)),
        ]);
        self.db
            .writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::upsert("incidents", "id", inc),
                RowWrite::insert("incident_events", ev),
            ]))
            .await
            .unwrap();
    }

    /// What `Incidents::acknowledge` leaves in the row.
    async fn ack(&self, id: &str, at: i64) {
        let conn = rusqlite::Connection::open(&self.path).unwrap();
        conn.execute(
            "UPDATE incidents SET acked_at = ?2, acked_by = 'user:bob' WHERE id = ?1",
            rusqlite::params![id, at],
        )
        .unwrap();
    }
}

const OPENED: &str = r#"{"severity":"critical","callout":true}"#;
const OPENED_WARNING: &str = r#"{"severity":"warning","callout":true}"#;

fn message(kind: MessageKind, severity: &str, incidents: Vec<CalloutIncident>) -> Message {
    Message { kind, severity: severity.into(), incidents, at_ms: T0 }
}

fn callout(title: &str, description: &str) -> CalloutIncident {
    CalloutIncident {
        id: "01JD00000000000000000000I1".into(),
        site: "home".into(),
        machine: "web".into(),
        severity: "critical".into(),
        title: title.into(),
        description: description.into(),
    }
}

#[test]
fn discord_payload_matches_format() {
    let long = "x".repeat(2500);
    let msg = message(MessageKind::Callout, "critical", vec![callout("disk.used_pct over 95", &long)]);
    let p = discord::payload(&msg, Some("https://hub.example.net"));
    assert_eq!(p["username"], "Rackhand");
    let embed = &p["embeds"][0];
    assert_eq!(embed["title"], "CRITICAL home/web: disk.used_pct over 95");
    assert_eq!(embed["color"], discord::RED);
    assert!(embed["description"].as_str().unwrap().chars().count() <= 2000);
    assert_eq!(embed["url"], "https://hub.example.net/incidents/01JD00000000000000000000I1");
    assert_eq!(embed["timestamp"], "2026-11-19T06:00:00Z");
    let fields: Vec<&str> = embed["fields"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert_eq!(fields, ["Site", "Machine", "Severity"]);
    let warn =
        discord::payload(&message(MessageKind::Group, "warning", vec![callout("a", ""), callout("b", "")]), None);
    assert_eq!(warn["embeds"][0]["color"], discord::AMBER);
    assert!(warn["embeds"][0].get("url").is_none(), "no url without a dashboard URL");
    let resolved = discord::payload(&message(MessageKind::Resolution, "critical", vec![callout("a", "")]), None);
    assert_eq!(resolved["embeds"][0]["color"], discord::GREEN);
}

/// A local webhook that answers 429 (retry after 2.5 s) to the first request and 204 after.
async fn webhook() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: String| {
            let counter = counter.clone();
            async move {
                assert!(body.contains("\"username\":\"Rackhand\""));
                if counter.fetch_add(1, Ordering::Relaxed) == 0 {
                    (axum::http::StatusCode::TOO_MANY_REQUESTS, r#"{"retry_after": 2.5}"#.to_string())
                } else {
                    (axum::http::StatusCode::NO_CONTENT, String::new())
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), hits)
}

#[tokio::test(flavor = "multi_thread")]
async fn discord_429_retry_after_respected() {
    let (url, hits) = webhook().await;
    let discord: Arc<dyn Transport> = Arc::new(discord::Discord::new("discord", &url));
    let env = env("discord429", vec![discord]).await;
    env.incident("01JD00000000000000000000I1", M1, ("critical", "open"), ("opened", OPENED), T0).await;
    env.notify.tick(T0).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 1, "sent once, answered 429");
    env.notify.tick(T0 + 2_400).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 1, "not before retry_after");
    env.notify.tick(T0 + 2_500).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 2, "again after 2.5 s");
    let state: String = env
        .db
        .readers()
        .with(|c| c.query_row("SELECT state FROM notifications ORDER BY at_ms DESC LIMIT 1", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(state, "sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_subject_and_multipart_body() {
    let sink = smtp_sink::Sink::start().await;
    let config = smtp::SmtpConfig {
        host: "localhost".into(),
        port: sink.port,
        security: smtp::Security::StartTls,
        username: Some("hub".into()),
        password: Some("pw".into()),
        from: "hub@example.net".into(),
        to: vec!["ops@example.net".into()],
        extra_roots: vec![sink.cert.clone()],
    };
    let smtp = smtp::Smtp::new("mail", config);
    let msg = message(MessageKind::Callout, "critical", vec![callout("disk.used_pct over 95", "/var is 96% full")]);
    smtp.send(&msg).await.unwrap();
    let mail = sink.received().await;
    assert!(mail.tls, "STARTTLS before AUTH");
    assert_eq!(mail.auth.as_deref(), Some("\0hub\0pw"));
    assert_eq!(mail.rcpt, ["ops@example.net"]);
    assert!(mail.data.contains("Subject: [Rackhand] CRITICAL home/web: disk.used_pct over 95\r\n"), "{}", mail.data);
    assert!(mail.data.contains("Content-Type: multipart/alternative; boundary="));
    assert!(mail.data.contains("Content-Type: text/plain; charset=utf-8"));
    assert!(mail.data.contains("Content-Type: text/html; charset=utf-8"));
    assert!(mail.data.contains("/var is 96% full"));
}

#[tokio::test(flavor = "multi_thread")]
async fn critical_sent_immediately_warnings_grouped_5_min() {
    let fake = Fake::new("fake");
    let env = env("grouping", vec![fake.clone()]).await;
    env.incident("01JD00000000000000000000I1", M1, ("critical", "open"), ("opened", OPENED), T0).await;
    env.incident("01JD00000000000000000000I2", M1, ("warning", "open"), ("opened", OPENED_WARNING), T0).await;
    env.notify.tick(T0).await.unwrap();
    let sent = fake.sent();
    assert_eq!(sent.len(), 1, "the critical at once");
    assert_eq!((sent[0].kind, sent[0].severity.as_str()), (MessageKind::Callout, "critical"));
    env.incident("01JD00000000000000000000I3", M2, ("warning", "open"), ("opened", OPENED_WARNING), T0 + 2 * MIN).await;
    env.notify.tick(T0 + 4 * MIN).await.unwrap();
    assert_eq!(fake.sent().len(), 1, "warnings wait for the group");
    env.notify.tick(T0 + 5 * MIN).await.unwrap();
    let sent = fake.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].kind, MessageKind::Group);
    assert_eq!(sent[1].incidents.len(), 2, "one message lists both warnings of the site");
}

#[tokio::test(flavor = "multi_thread")]
async fn resent_on_rise_and_every_6h_unacked_and_not_before() {
    let fake = Fake::new("fake");
    let env = env("resend", vec![fake.clone()]).await;
    let id = "01JD00000000000000000000I1";
    env.incident(id, M1, ("critical", "open"), ("opened", OPENED), T0).await;
    env.notify.tick(T0).await.unwrap();
    env.notify.tick(T0 + 6 * HOUR - MIN).await.unwrap();
    assert_eq!(fake.sent().len(), 1, "nothing at 5 h 59 min");
    env.notify.tick(T0 + 6 * HOUR).await.unwrap();
    assert_eq!(fake.sent().len(), 2, "re-sent at 6 h");
    // a rise sends again at once; a fall doesn't
    env.incident(
        id,
        M1,
        ("warning", "open"),
        ("severity", r#"{"from":"critical","to":"warning","callout":false}"#),
        T0 + 7 * HOUR,
    )
    .await;
    env.notify.tick(T0 + 7 * HOUR).await.unwrap();
    assert_eq!(fake.sent().len(), 2, "a fall sends nothing");
    env.incident(
        id,
        M1,
        ("critical", "open"),
        ("severity", r#"{"from":"warning","to":"critical","callout":true}"#),
        T0 + 8 * HOUR,
    )
    .await;
    env.notify.tick(T0 + 8 * HOUR).await.unwrap();
    assert_eq!(fake.sent().len(), 3, "a rise sends at once");
    env.ack(id, T0 + 9 * HOUR).await;
    env.notify.tick(T0 + 15 * HOUR).await.unwrap();
    assert_eq!(fake.sent().len(), 3, "acknowledged: no more re-sends");
}

#[tokio::test(flavor = "multi_thread")]
async fn resolution_sent_for_called_out_incidents_only() {
    let fake = Fake::new("fake");
    let env = env("resolution", vec![fake.clone()]).await;
    env.incident("01JD00000000000000000000I1", M1, ("critical", "open"), ("opened", OPENED), T0).await;
    env.incident(
        "01JD00000000000000000000I2",
        M1,
        ("info", "open"),
        ("opened", r#"{"severity":"info","callout":true}"#),
        T0,
    )
    .await;
    env.notify.tick(T0).await.unwrap();
    env.incident(
        "01JD00000000000000000000I1",
        M1,
        ("critical", "resolved"),
        ("resolved", r#"{"by":"condition"}"#),
        T0 + MIN,
    )
    .await;
    env.incident(
        "01JD00000000000000000000I2",
        M1,
        ("info", "resolved"),
        ("resolved", r#"{"by":"condition"}"#),
        T0 + MIN,
    )
    .await;
    env.notify.tick(T0 + MIN).await.unwrap();
    let kinds: Vec<(MessageKind, String)> = fake.sent().iter().map(|m| (m.kind, m.incidents[0].id.clone())).collect();
    assert_eq!(
        kinds,
        vec![
            (MessageKind::Callout, "01JD00000000000000000000I1".to_string()),
            (MessageKind::Resolution, "01JD00000000000000000000I1".to_string())
        ],
        "info is dashboard only, so it gets no callout and no resolution"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retries_1_5_15_then_failed_raises_notifier_failed() {
    let broken = Fake::new("discord");
    broken.fail.store(true, Ordering::Relaxed);
    let working = Fake::new("mail");
    let env = env("retries", vec![broken.clone(), working.clone()]).await;
    env.incident("01JD00000000000000000000I1", M1, ("critical", "open"), ("opened", OPENED), T0).await;
    let at = [0, MIN, 6 * MIN, 21 * MIN];
    env.notify.tick(T0).await.unwrap();
    for minute in 1..=21 {
        env.notify.tick(T0 + minute * MIN).await.unwrap();
    }
    assert_eq!(broken.attempts.load(Ordering::Relaxed), at.len(), "the first try and retries at 1, 5 and 15 minutes");
    let events: Vec<(String, String)> = env
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT kind, severity FROM events")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap();
    assert_eq!(events, vec![("notifier_failed".to_string(), "warning".to_string())]);
    let kinds: Vec<MessageKind> = working.sent().iter().map(|m| m.kind).collect();
    assert_eq!(kinds, [MessageKind::Callout, MessageKind::NotifierFailed], "told through the notifier that works");
    env.notify.tick(T0 + 40 * MIN).await.unwrap();
    assert_eq!(broken.attempts.load(Ordering::Relaxed), 4, "no more attempts after failing");
}

#[tokio::test(flavor = "multi_thread")]
async fn callouts_carry_no_secrets_or_command_output() {
    let fake = Fake::new("fake");
    let env = env("secrets", vec![fake.clone()]).await;
    let id = "01JD00000000000000000000I1";
    env.incident(id, M1, ("critical", "open"), ("opened", OPENED), T0).await;
    let job = Row::from([
        ("id", t("01JD00000000000000000000J1")),
        ("kind", t("runbook")),
        ("name", t("restart-web")),
        ("requested_by", t("incident")),
        ("incident_id", t(id)),
        ("state", t("failed")),
    ]);
    let step = Row::from([
        ("job_id", t("01JD00000000000000000000J1")),
        ("step_id", t("s1")),
        ("state", t("failed")),
        ("stdout", Value::Blob(b"token=SECRET-1234 password=hunter2".to_vec())),
    ]);
    env.db
        .writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert("jobs", job), RowWrite::insert("job_steps", step)]))
        .await
        .unwrap();
    env.notify.tick(T0).await.unwrap();
    let msg = fake.sent().pop().unwrap();
    let all = format!("{} {}", discord::payload(&msg, Some("https://hub.example.net")), smtp::body_text(&msg));
    for secret in ["SECRET-1234", "hunter2", "token="] {
        assert!(!all.contains(secret), "{secret} in {all}");
    }
    assert!(!all.contains("approve") && !all.contains("/act"), "no links that act without signing in");
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_step_sends_through_every_notifier() {
    let fake = Fake::new("fake");
    let env = env("step", vec![fake.clone()]).await;
    env.notify.send_text("Backup of web finished", T0).await.unwrap();
    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].kind, sent[0].incidents[0].title.as_str()), (MessageKind::Text, "Backup of web finished"));
}

#[test]
fn smtp_header_injection_stripped() {
    let config = smtp::SmtpConfig {
        host: "localhost".into(),
        port: 25,
        security: smtp::Security::StartTls,
        username: None,
        password: None,
        from: "hub@example.net".into(),
        to: vec!["ops@example.net".into()],
        extra_roots: Vec::new(),
    };
    // an event incident's title carries a subject the machine reported
    let msg =
        message(MessageKind::Callout, "warning", vec![callout("auth.root_login: x\r\nBcc: evil@example.net", "d")]);
    let mail = smtp::mime_for_test(&config, &msg);
    let headers = mail.split("\r\n\r\n").next().unwrap();
    assert!(!headers.lines().any(|l| l.starts_with("Bcc:")), "{headers}");
    assert!(headers.contains("Subject: [Rackhand] WARNING home/web: auth.root_login: x Bcc: evil@example.net"));
}
