//! Logs (design 13): JSON lines on stderr, which journald keeps, at info unless `RACKHAND_LOG` names another filter
//! (`debug`, `warn`, `rackhand_hub=debug`, ...).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The subscriber: JSON lines to `writer`, filtered by `filter` (info when it's missing or doesn't parse).
pub fn subscriber<W>(filter: Option<&str>, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = filter.and_then(|f| EnvFilter::try_new(f).ok()).unwrap_or_else(|| EnvFilter::new("info"));
    tracing_subscriber::fmt().json().with_env_filter(filter).with_ansi(false).with_writer(writer).finish()
}

/// Logs of a long-running command go to stderr from here on.
pub fn init() {
    let filter = std::env::var("RACKHAND_LOG").ok();
    let _ = tracing::subscriber::set_global_default(subscriber(filter.as_deref(), std::io::stderr));
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn lines(filter: Option<&str>) -> Vec<serde_json::Value> {
        let buf = Buf::default();
        let out = buf.clone();
        tracing::subscriber::with_default(subscriber(filter, move || out.clone()), || {
            tracing::debug!("a detail");
            tracing::warn!(machine = "m1", "join refused");
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        text.lines().map(|l| serde_json::from_str(l).expect("each line is JSON")).collect()
    }

    #[test]
    fn json_lines_at_info_by_default() {
        let got = lines(None);
        assert_eq!(got.len(), 1, "debug is filtered out: {got:?}");
        assert_eq!(got[0]["level"], "WARN");
        assert_eq!(got[0]["fields"]["message"], "join refused");
        assert_eq!(got[0]["fields"]["machine"], "m1");
        assert!(got[0]["timestamp"].is_string());
        assert_eq!(lines(Some("debug")).len(), 2, "RACKHAND_LOG=debug shows details");
        assert_eq!(lines(Some("not a [filter")).len(), 1, "a bad filter falls back to info");
    }
}
