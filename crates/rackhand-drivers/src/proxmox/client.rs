//! The Proxmox VE API client: HTTPS to the node with its certificate pinned (`crate::pinned`) and an API token
//! (`PVEAPIToken=<user>@<realm>!<id>=<secret>`).

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::Value;

use crate::driver::{DriverError, DriverTarget, settings, text};

const MAX_BODY: usize = 8 << 20;

/// One segment of a path, escaped (a task's UPID has `:` in it).
pub(crate) fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) struct Client {
    host: String,
    port: u16,
    token: String,
    timeout: std::time::Duration,
    tls: tokio_rustls::TlsConnector,
    /// The `node` setting, when the host is one node of a cluster the token sees more of.
    pub node: Option<String>,
}

impl Client {
    pub const SETTINGS: &'static [&'static str] = &["token", "fingerprint", "node"];

    pub fn new(target: &DriverTarget) -> Result<Client, DriverError> {
        let s = settings(&target.settings, Client::SETTINGS)?;
        let token = text(s, "token")?.ok_or_else(|| DriverError::Invalid("the API token (`token`)".into()))?;
        if !token.contains('!') || !token.contains('=') {
            return Err(DriverError::Invalid("the token is <user>@<realm>!<id>=<secret>".into()));
        }
        let tls = crate::pinned::connector(text(s, "fingerprint")?)?;
        let raw =
            if target.target.contains("://") { target.target.clone() } else { format!("https://{}", target.target) };
        let url = url::Url::parse(&raw).map_err(|e| DriverError::Invalid(format!("the address: {e}")))?;
        if url.scheme() != "https" {
            return Err(DriverError::Invalid("the Proxmox API is https".into()));
        }
        let host = url.host_str().ok_or_else(|| DriverError::Invalid("the address has no host".into()))?.to_string();
        let port = url.port().unwrap_or(8006);
        Ok(Client {
            host,
            port,
            token: token.to_string(),
            timeout: target.timeout,
            tls,
            node: text(s, "node")?.map(str::to_string),
        })
    }

    /// One request; returns the answer's `data`. `form` is the request's form body (or nothing).
    pub async fn call(&self, method: &str, path: &str, form: &[(String, String)]) -> Result<Value, DriverError> {
        let attempt = async {
            let tls = crate::pinned::connect(&self.tls, &self.host, self.port).await?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            let body: String = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
            let mut req = hyper::Request::builder()
                .method(method)
                .uri(format!("/api2/json{path}"))
                .header(hyper::header::HOST, &self.host)
                .header(hyper::header::AUTHORIZATION, format!("PVEAPIToken={}", self.token));
            if !body.is_empty() {
                req = req.header(hyper::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            let req = req.body(Full::new(Bytes::from(body))).map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let bytes = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok::<_, String>((status, bytes))
        };
        let (status, bytes) = match tokio::time::timeout(self.timeout, attempt).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(DriverError::Failed(e)),
            Err(_) => return Err(DriverError::Failed(format!("{method} {path}: no answer within {:?}", self.timeout))),
        };
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            let why = json["message"].as_str().map(str::trim).unwrap_or("").to_string();
            return Err(DriverError::Failed(format!("{method} {path}: {status} {why}").trim().to_string()));
        }
        Ok(json["data"].clone())
    }
}
