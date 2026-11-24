//! The production [`Fetch`]: one HTTPS GET with the public roots, at most three redirects (to https only), a size cap and a
//! time limit; anything but a 200 is an error.

use std::time::Duration;

use axum::http::Method;

use super::Fetch;

const TIMEOUT: Duration = Duration::from_secs(120);
const REDIRECTS: usize = 3;

#[derive(Debug, Default, Clone, Copy)]
pub struct Https;

async fn get(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..=REDIRECTS {
        let accept = [("accept-encoding", "identity")];
        let response = crate::http::request_up_to(Method::GET, &url, &accept, Vec::new(), TIMEOUT, max_bytes).await?;
        match response.status {
            200 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                let to = response.header("location").ok_or("a redirect with no location")?.to_string();
                if !to.starts_with("https://") {
                    return Err(format!("a redirect to {to}, which isn't https"));
                }
                url = to;
            }
            other => return Err(format!("{other} from {url}")),
        }
    }
    Err("too many redirects".into())
}

impl Fetch for Https {
    fn get<'a>(
        &'a self,
        url: &'a str,
        max_bytes: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(get(url, max_bytes))
    }
}
