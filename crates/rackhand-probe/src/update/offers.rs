//! What the probe does with an `UpdateAvailable` (7.3.3): ignore it unless it is newer than the running version, download the
//! release into the spool, and ask the helper to apply it. The hub offers again whenever a probe connects, so the same version
//! isn't tried again for ten minutes.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use rackhand_proto::helper::{HelperRequest, HelperResponse};
use rackhand_proto::probe::UpdateAvailable;
use rackhand_release::binary::Version;

use super::download::{Failure, Offer, fetch, parse_offer, worth_trying};

const RETRY_AFTER_MS: i64 = 10 * 60_000;
/// The whole download.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Default)]
pub struct Offers {
    /// When each version was last tried.
    tried: HashMap<Version, i64>,
}

impl Offers {
    /// The offer, when it is well formed, newer than `running`, and not tried in the last ten minutes.
    pub fn accept(&mut self, update: &UpdateAvailable, running: &str, now_ms: i64) -> Option<Offer> {
        let running = Version::parse(running)?;
        let offer = parse_offer(update).ok()?;
        if !worth_trying(running, offer.version) {
            return None;
        }
        if self.tried.get(&offer.version).is_some_and(|at| now_ms - at < RETRY_AFTER_MS) {
            return None;
        }
        self.tried.insert(offer.version, now_ms);
        Some(offer)
    }
}

/// Downloads the offer into `spool`, then asks the helper (`ask` sends it one request) to apply it. `Ok` means the helper
/// started the switch; the probe is restarted by the guard if it works.
pub async fn perform<F, Fut>(spool: &Path, offer: &Offer, timeout: Duration, ask: F) -> Result<(), Failure>
where
    F: FnOnce(HelperRequest) -> Fut,
    Fut: Future<Output = Result<HelperResponse, String>>,
{
    fetch(spool, offer, timeout).await?;
    match ask(offer.request()).await {
        Ok(HelperResponse::UpdateStarted) => Ok(()),
        Ok(HelperResponse::Error { code, message }) => Err(Failure::Refused(format!("{code}: {message}"))),
        Ok(other) => Err(Failure::Refused(format!("the helper answered {other:?}"))),
        Err(e) => Err(Failure::Refused(format!("the helper: {e}"))),
    }
}

#[cfg(test)]
mod tests;
