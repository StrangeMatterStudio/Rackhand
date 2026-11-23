//! `rackhand relay ...` (7.3.10): run the relay, and issue the keys a hub presents to it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use rackhand_relay::admission::Mode;
use rackhand_relay::keys::{self, KeyBody, Priority};
use rackhand_relay::run::{Certificate, RelayRun};

pub const USAGE: &str =
    "       rackhand relay run [--data-dir <dir>] [--mode private|public] [--rate <bits/s>] [--http <addr>]
                          [--https <addr>] [--quic <addr>]
                          [--acme-domain <name>]... --acme-contact <mailto:address> [--acme-staging]
                          [--cert <chain.pem> --key <key.pem>]
       rackhand relay key create --name <name> --expires <YYYY-MM-DD> [--priority normal|high] [--max-endpoints <n>]
                          [--data-dir <dir>]";

const DEFAULT_DIR: &str = "/var/lib/rackhand-relay";

/// `--name value` pairs, with `--acme-domain` allowed more than once and `--acme-staging` a flag.
#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    values: Vec<(String, String)>,
}

impl Options {
    fn parse(rest: &[&str], allowed: &[&str], flags: &[&str]) -> Result<Options, String> {
        let mut out = Options::default();
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            let name = arg
                .strip_prefix("--")
                .filter(|n| allowed.contains(n) || flags.contains(n))
                .ok_or_else(|| format!("unknown option `{arg}`"))?;
            if flags.contains(&name) {
                out.values.push((name.to_string(), String::new()));
                continue;
            }
            let value = it.next().ok_or_else(|| format!("`--{name}` needs a value"))?;
            if out.get(name).is_some() && name != "acme-domain" {
                return Err(format!("`--{name}` given twice"));
            }
            out.values.push((name.to_string(), (*value).to_string()));
        }
        Ok(out)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values.iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
    }

    fn address(&self, name: &str, default: &str) -> Result<SocketAddr, String> {
        let text = self.get(name).unwrap_or(default);
        text.parse().map_err(|_| format!("`--{name} {text}` isn't an address like 0.0.0.0:443"))
    }
}

/// What `relay run` was asked for.
fn run_config(rest: &[&str]) -> Result<RelayRun, String> {
    let o = Options::parse(
        rest,
        &["data-dir", "mode", "rate", "http", "https", "quic", "acme-domain", "acme-contact", "cert", "key"],
        &["acme-staging"],
    )?;
    let mode = match o.get("mode").unwrap_or("private") {
        "private" => Mode::Private,
        "public" => Mode::Public,
        other => return Err(format!("`--mode {other}`: private or public")),
    };
    let rate_bits = match o.get("rate") {
        None => None,
        Some(r) => {
            Some(r.parse::<u32>().ok().filter(|r| *r > 0).ok_or_else(|| format!("`--rate {r}`: bits per second"))?)
        }
    };
    let domains = o.all("acme-domain");
    let certificate = match (domains.is_empty(), o.get("cert"), o.get("key")) {
        (false, None, None) => {
            let contact = o.get("acme-contact").ok_or("Let's Encrypt needs `--acme-contact mailto:<address>`")?;
            Certificate::Acme {
                domains,
                contact: vec![contact.to_string()],
                production: !o.values.iter().any(|(n, _)| n == "acme-staging"),
            }
        }
        (true, Some(cert), Some(key)) => Certificate::Files { cert: cert.into(), key: key.into() },
        (true, None, None) => Certificate::None,
        _ => return Err("use `--acme-domain` or `--cert` with `--key`, not both, and `--cert` needs `--key`".into()),
    };
    Ok(RelayRun {
        data_dir: PathBuf::from(o.get("data-dir").unwrap_or(DEFAULT_DIR)),
        mode,
        http: o.address("http", "0.0.0.0:80")?,
        https: o.address("https", "0.0.0.0:443")?,
        quic: o.address("quic", "0.0.0.0:7842")?,
        certificate,
        rate_bits,
        capacity: rackhand_relay::admission::CAPACITY,
    })
}

/// The first millisecond after `date` (`YYYY-MM-DD`) has ended in UTC: a key made to expire on a date works through it.
fn expiry_ms(date: &str) -> Result<i64, String> {
    let day: jiff::civil::Date = date.parse().map_err(|_| format!("`--expires {date}`: a date like 2027-01-31"))?;
    let next = day.tomorrow().map_err(|e| e.to_string())?;
    let at = next.to_zoned(jiff::tz::TimeZone::UTC).map_err(|e| e.to_string())?;
    Ok(at.timestamp().as_millisecond())
}

/// A token for `relay key create`, signed with the relay's own key in the data directory.
fn create_key(rest: &[&str], now_ms: i64) -> Result<String, String> {
    let o = Options::parse(rest, &["name", "expires", "priority", "max-endpoints", "data-dir"], &[])?;
    let name = o.get("name").filter(|n| !n.trim().is_empty()).ok_or("`--name` is required")?;
    let expires_ms = expiry_ms(o.get("expires").ok_or("`--expires` is required")?)?;
    if expires_ms <= now_ms {
        return Err("`--expires` is a date in the past".into());
    }
    let priority = match o.get("priority") {
        None => Priority::Normal,
        Some(p) => Priority::parse(p).ok_or_else(|| format!("`--priority {p}`: normal or high"))?,
    };
    let max_endpoints = match o.get("max-endpoints") {
        None => 1,
        Some(n) => {
            n.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(|| format!("`--max-endpoints {n}`: a number"))?
        }
    };
    let dir = PathBuf::from(o.get("data-dir").unwrap_or(DEFAULT_DIR));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let signing = rackhand_relay::run::signing_key(&dir)?;
    Ok(keys::create(&signing, &KeyBody { name: name.to_string(), priority, max_endpoints, expires_ms }))
}

async fn serve(config: &RelayRun) -> Result<(), String> {
    let (server, _admission) = rackhand_relay::run::run(config).await?;
    for (what, addr) in [("http", server.http_addr()), ("https", server.https_addr()), ("quic", server.quic_addr())] {
        if let Some(addr) = addr {
            tracing::info!(%addr, what, "the relay is listening");
        }
    }
    wait_for_stop().await;
    tracing::info!("the relay is stopping");
    server.shutdown().await.map_err(|e| e.to_string())
}

async fn wait_for_stop() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

pub fn main(rest: &[&str]) -> ExitCode {
    let failed = |e: String| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    };
    match rest {
        ["run", rest @ ..] => {
            let config = match run_config(rest) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}\nusage:\n{USAGE}");
                    return ExitCode::from(2);
                }
            };
            crate::logging::init();
            if matches!(config.certificate, Certificate::None) {
                tracing::warn!(
                    "no certificate: the relay speaks plain HTTP, for use behind something that terminates TLS"
                );
            }
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => return failed(e.to_string()),
            };
            match rt.block_on(serve(&config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => failed(e),
            }
        }
        ["key", "create", rest @ ..] => match create_key(rest, rackhand_store::ids::now_ms()) {
            Ok(token) => {
                println!("{token}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}\nusage:\n{USAGE}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("usage:\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("rackhand-relay-cmd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.display().to_string()
    }

    #[test]
    fn run_options_and_their_defaults() {
        let c = run_config(&[]).unwrap();
        assert_eq!(c.mode, Mode::Private);
        assert_eq!((c.rate_bits, c.https.port(), c.http.port(), c.quic.port()), (None, 443, 80, 7842));
        assert!(matches!(c.certificate, Certificate::None));
        let c = run_config(&["--mode", "public", "--rate", "2000000", "--https", "0.0.0.0:8443"]).unwrap();
        assert_eq!((c.mode, c.rate_bits, c.https.port()), (Mode::Public, Some(2_000_000), 8443));
        let c = run_config(&[
            "--acme-domain",
            "a.example.org",
            "--acme-domain",
            "b.example.org",
            "--acme-contact",
            "mailto:x@example.org",
        ])
        .unwrap();
        assert!(matches!(&c.certificate, Certificate::Acme { domains, production: true, .. } if domains.len() == 2));
        let c = run_config(&["--cert", "c.pem", "--key", "k.pem"]).unwrap();
        assert!(matches!(c.certificate, Certificate::Files { .. }));
        for (bad, why) in [
            (vec!["--mode", "open"], "private or public"),
            (vec!["--rate", "0"], "bits per second"),
            (vec!["--http", "nowhere"], "isn't an address"),
            (vec!["--cert", "c.pem"], "needs `--key`"),
            (vec!["--acme-domain", "a.example.org"], "--acme-contact"),
            (
                vec!["--acme-domain", "a.example.org", "--acme-contact", "mailto:x@y.z", "--cert", "c", "--key", "k"],
                "not both",
            ),
            (vec!["--mode"], "needs a value"),
            (vec!["--mode", "public", "--mode", "private"], "twice"),
            (vec!["--turbo", "1"], "unknown option"),
        ] {
            let e = run_config(&bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn key_create_signs_with_the_relays_key() {
        let data = dir("key");
        let now = 1_000;
        let token = create_key(
            &[
                "--name",
                "home",
                "--expires",
                "2999-01-31",
                "--priority",
                "high",
                "--max-endpoints",
                "2",
                "--data-dir",
                &data,
            ],
            now,
        )
        .unwrap();
        // the relay verifies it with the key that lives in its data directory, and no other relay would
        let relay = rackhand_relay::run::signing_key(std::path::Path::new(&data)).unwrap();
        let body = keys::verify(&relay.verifying_key(), &token, now).unwrap();
        assert_eq!((body.name.as_str(), body.priority, body.max_endpoints), ("home", Priority::High, 2));
        let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        assert!(keys::verify(&other.verifying_key(), &token, now).is_err());
        // it works through the whole of its last day, and not after
        assert_eq!(body.expires_ms, expiry_ms("2999-01-31").unwrap());
        assert_eq!(expiry_ms("2999-01-31").unwrap() - expiry_ms("2999-01-30").unwrap(), 86_400_000);
        // defaults: a normal key for one endpoint
        let token = create_key(&["--name", "n", "--expires", "2999-01-31", "--data-dir", &data], now).unwrap();
        let body = keys::verify(&relay.verifying_key(), &token, now).unwrap();
        assert_eq!((body.priority, body.max_endpoints), (Priority::Normal, 1));
        for (bad, why) in [
            (vec!["--expires", "2999-01-31"], "--name"),
            (vec!["--name", "n"], "--expires"),
            (vec!["--name", "n", "--expires", "soon"], "a date like"),
            (vec!["--name", "n", "--expires", "1999-01-31"], "in the past"),
            (vec!["--name", "n", "--expires", "2999-01-31", "--priority", "urgent"], "normal or high"),
            (vec!["--name", "n", "--expires", "2999-01-31", "--max-endpoints", "0"], "a number"),
        ] {
            let mut args = bad.clone();
            args.extend(["--data-dir", &data]);
            let e = create_key(&args, 1_700_000_000_000).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let _ = std::fs::remove_dir_all(&data);
    }
}
