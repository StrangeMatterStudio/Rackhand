//! The offline test's LAN mail server (plan T97): the hub's SMTP sink, listening on an address of the test's network
//! with a certificate for that address, so the hub reaches it with no DNS. It writes its certificate to
//! `<dir>/cert.pem` and each mail it receives to `<dir>/mail-<n>.eml`, a first line saying whether the session used TLS.
//!
//! `smtp_sink <bind address:port> <address the certificate names> <dir>`

use std::path::{Path, PathBuf};

use rackhand_hub::notify::smtp_sink::Sink;

/// Written whole: the test never reads half a file.
fn write(dir: &Path, name: &str, text: &str) -> std::io::Result<()> {
    let part = dir.join(format!(".{name}.part"));
    std::fs::write(&part, text)?;
    std::fs::rename(part, dir.join(name))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [bind, name, dir] = args.as_slice() else {
        eprintln!("usage: smtp_sink <bind address:port> <address the certificate names> <dir>");
        std::process::exit(2);
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir)?;
    let sink = Sink::start_at(bind, name).await;
    write(&dir, "cert.pem", &sink.cert_pem)?;
    for n in 1.. {
        let mail = sink.next().await;
        let text = format!("X-Sink-TLS: {}\r\nX-Sink-Rcpt: {}\r\n{}", mail.tls, mail.rcpt.join(", "), mail.data);
        write(&dir, &format!("mail-{n:03}.eml"), &text)?;
    }
    Ok(())
}
