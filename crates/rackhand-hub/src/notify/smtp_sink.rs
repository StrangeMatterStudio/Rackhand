//! An in-process SMTP receiver for tests: EHLO, STARTTLS with a self-signed certificate, AUTH PLAIN, MAIL, RCPT, DATA.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Default)]
pub struct Mail {
    pub tls: bool,
    pub auth: Option<String>,
    pub rcpt: Vec<String>,
    pub data: String,
}

#[derive(Debug)]
pub struct Sink {
    pub port: u16,
    pub cert: CertificateDer<'static>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Mail>>,
}

enum Phase {
    StartTls,
    Done,
}

async fn reply<S: AsyncWrite + Unpin>(s: &mut S, text: &str) -> std::io::Result<()> {
    s.write_all(text.as_bytes()).await?;
    s.flush().await
}

/// Runs commands until the client asks for STARTTLS (on a plain stream) or the mail is done.
async fn commands<S: AsyncRead + AsyncWrite + Unpin>(s: &mut BufReader<S>, mail: &mut Mail) -> std::io::Result<Phase> {
    loop {
        let mut line = String::new();
        if s.read_line(&mut line).await? == 0 {
            return Ok(Phase::Done);
        }
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let tls = if mail.tls { "" } else { "250-STARTTLS\r\n" };
            reply(s.get_mut(), &format!("250-sink\r\n{tls}250 AUTH PLAIN\r\n")).await?;
        } else if upper.starts_with("STARTTLS") {
            reply(s.get_mut(), "220 ready\r\n").await?;
            return Ok(Phase::StartTls);
        } else if upper.starts_with("AUTH PLAIN") {
            let b64 = line.trim_end()[10..].trim();
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
            mail.auth = Some(String::from_utf8_lossy(&raw).into_owned());
            reply(s.get_mut(), "235 ok\r\n").await?;
        } else if upper.starts_with("MAIL FROM") {
            reply(s.get_mut(), "250 ok\r\n").await?;
        } else if upper.starts_with("RCPT TO") {
            let addr = line.trim_end().split(['<', '>']).nth(1).unwrap_or_default().to_string();
            mail.rcpt.push(addr);
            reply(s.get_mut(), "250 ok\r\n").await?;
        } else if upper.starts_with("DATA") {
            reply(s.get_mut(), "354 go\r\n").await?;
            loop {
                let mut l = String::new();
                if s.read_line(&mut l).await? == 0 || l == ".\r\n" {
                    break;
                }
                mail.data.push_str(&l);
            }
            reply(s.get_mut(), "250 queued\r\n").await?;
        } else if upper.starts_with("QUIT") {
            reply(s.get_mut(), "221 bye\r\n").await?;
            return Ok(Phase::Done);
        } else {
            reply(s.get_mut(), "502 no\r\n").await?;
        }
    }
}

impl Sink {
    pub async fn start() -> Sink {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let cert = generated.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let mut mail = Mail::default();
                    let mut plain = BufReader::new(tcp);
                    if reply(plain.get_mut(), "220 sink ESMTP\r\n").await.is_err() {
                        return;
                    }
                    if let Ok(Phase::StartTls) = commands(&mut plain, &mut mail).await {
                        let Ok(tls) = acceptor.accept(plain.into_inner()).await else { return };
                        mail.tls = true;
                        let _ = commands(&mut BufReader::new(tls), &mut mail).await;
                    }
                    let _ = tx.send(mail).await;
                });
            }
        });
        Sink { port, cert, rx: tokio::sync::Mutex::new(rx) }
    }

    pub async fn received(&self) -> Mail {
        tokio::time::timeout(Duration::from_secs(10), self.rx.lock().await.recv())
            .await
            .expect("a mail within 10 s")
            .expect("the sink is running")
    }
}
