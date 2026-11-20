//! SMTP (7.3.9): STARTTLS or implicit TLS, a plain text and an HTML part, subject
//! `[Rackhand] <SEVERITY> <site>/<machine>: <title>`.

use std::time::Duration;

use base64::Engine;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use super::discord::headline;
use super::{BoxFuture, Message, MessageKind, SendError, Transport};

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Plain connection upgraded with STARTTLS before anything else is sent (port 587).
    StartTls,
    /// TLS from the first byte (port 465).
    Tls,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    /// Roots trusted besides the public ones (a mail server with its own CA).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

#[derive(Debug)]
pub struct Smtp {
    name: String,
    config: SmtpConfig,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A header value on one line: CR and LF (which could start another header) become a single space.
fn one_line(s: &str) -> String {
    s.split(['\r', '\n']).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ")
}

pub fn subject(msg: &Message) -> String {
    one_line(&format!("[Rackhand] {}", headline(msg)))
}

/// The plain text part.
pub fn body_text(msg: &Message) -> String {
    match msg.kind {
        MessageKind::Group => msg
            .incidents
            .iter()
            .map(|i| format!("- {}/{}: {}", i.site, i.machine, i.title))
            .collect::<Vec<_>>()
            .join("\r\n"),
        _ => msg.incidents.first().map(|i| i.description.clone()).unwrap_or_default(),
    }
}

fn body_html(msg: &Message) -> String {
    let items: Vec<String> = match msg.kind {
        MessageKind::Group => msg
            .incidents
            .iter()
            .map(|i| format!("<li>{}/{}: {}</li>", esc(&i.site), esc(&i.machine), esc(&i.title)))
            .collect(),
        _ => msg.incidents.first().map(|i| format!("<p>{}</p>", esc(&i.description))).into_iter().collect(),
    };
    let body = if msg.kind == MessageKind::Group { format!("<ul>{}</ul>", items.join("")) } else { items.join("") };
    format!("<html><body><h3>{}</h3>{body}</body></html>", esc(&headline(msg)))
}

/// The whole message (headers and both parts), CRLF line ends, dot-stuffed for DATA.
fn mime(config: &SmtpConfig, msg: &Message) -> String {
    let boundary = format!("rackhand-{}", rackhand_store::ids::new_id());
    let date = jiff::Timestamp::from_millisecond(msg.at_ms)
        .map(|t| t.strftime("%a, %d %b %Y %H:%M:%S +0000").to_string())
        .unwrap_or_default();
    let domain = config.from.rsplit('@').next().unwrap_or("localhost");
    let mut out = String::new();
    out.push_str(&format!("From: {}\r\n", one_line(&config.from)));
    out.push_str(&format!("To: {}\r\n", one_line(&config.to.join(", "))));
    out.push_str(&format!("Subject: {}\r\n", subject(msg)));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!("Message-ID: <{}@{domain}>\r\n", rackhand_store::ids::new_id()));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"));
    out.push_str(&format!(
        "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    ));
    out.push_str(&body_text(msg));
    out.push_str(&format!(
        "\r\n--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    ));
    out.push_str(&body_html(msg));
    out.push_str(&format!("\r\n--{boundary}--\r\n"));
    out.split("\r\n")
        .map(|l| if l.starts_with('.') { format!(".{l}") } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Reads one reply (all its lines) and checks its code.
async fn expect(r: &mut BufReader<Box<dyn Io>>, code: &str) -> Result<String, String> {
    let mut text = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await.map_err(|e| e.to_string())? == 0 {
            return Err("the server closed the connection".into());
        }
        text.push_str(&line);
        if line.len() < 4 || line.as_bytes()[3] != b'-' {
            if !line.starts_with(code) {
                return Err(format!("expected {code}, got {}", line.trim_end()));
            }
            return Ok(text);
        }
    }
}

async fn command(r: &mut BufReader<Box<dyn Io>>, line: &str, code: &str) -> Result<String, String> {
    r.get_mut().write_all(format!("{line}\r\n").as_bytes()).await.map_err(|e| e.to_string())?;
    r.get_mut().flush().await.map_err(|e| e.to_string())?;
    expect(r, code).await
}

impl Smtp {
    pub fn new(name: &str, config: SmtpConfig) -> Smtp {
        Smtp { name: name.to_string(), config }
    }

    async fn deliver(&self, msg: &Message) -> Result<(), String> {
        let c = &self.config;
        let tcp = tokio::net::TcpStream::connect((c.host.as_str(), c.port)).await.map_err(|e| e.to_string())?;
        let tls = crate::http::tls(&c.extra_roots)?;
        let name = ServerName::try_from(c.host.clone()).map_err(|e| e.to_string())?;
        let io: Box<dyn Io> = match c.security {
            Security::Tls => Box::new(tls.connect(name.clone(), tcp).await.map_err(|e| e.to_string())?),
            Security::StartTls => Box::new(tcp),
        };
        let mut r = BufReader::new(io);
        expect(&mut r, "220").await?;
        command(&mut r, "EHLO rackhand", "250").await?;
        if c.security == Security::StartTls {
            command(&mut r, "STARTTLS", "220").await?;
            let plain = r.into_inner();
            let upgraded: Box<dyn Io> = Box::new(tls.connect(name, plain).await.map_err(|e| e.to_string())?);
            r = BufReader::new(upgraded);
            command(&mut r, "EHLO rackhand", "250").await?;
        }
        if let (Some(user), Some(pass)) = (&c.username, &c.password) {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
            command(&mut r, &format!("AUTH PLAIN {token}"), "235").await?;
        }
        command(&mut r, &format!("MAIL FROM:<{}>", c.from), "250").await?;
        for to in &c.to {
            command(&mut r, &format!("RCPT TO:<{to}>"), "250").await?;
        }
        command(&mut r, "DATA", "354").await?;
        r.get_mut().write_all(mime(c, msg).as_bytes()).await.map_err(|e| e.to_string())?;
        command(&mut r, "\r\n.", "250").await?;
        let _ = command(&mut r, "QUIT", "221").await;
        Ok(())
    }
}

impl Transport for Smtp {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(&'a self, msg: &'a Message) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            match tokio::time::timeout(TIMEOUT, self.deliver(msg)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(SendError::Failed(e)),
                Err(_) => Err(SendError::Failed("timed out".into())),
            }
        })
    }
}

#[cfg(test)]
pub fn mime_for_test(config: &SmtpConfig, msg: &Message) -> String {
    mime(config, msg)
}
