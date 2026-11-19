//! Cloud-init NoCloud seeds served over HTTP to machines on their first boot (plan L1). Machines reach the server at
//! the QEMU user-mode gateway, 10.0.2.2, so no ISO tools or root are needed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use super::config::{Lab, Machine};
use super::qemu;
use crate::workspace_root;

pub const PORT: u16 = 23100;

pub struct Server {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Server {
    pub fn start() -> Result<Server> {
        let listener =
            TcpListener::bind(("127.0.0.1", PORT)).with_context(|| format!("binding seed server on {PORT}"))?;
        let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let shared = files.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let files = shared.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(&stream);
                    let mut request = String::new();
                    if reader.read_line(&mut request).is_err() {
                        return;
                    }
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).map(|n| n == 0).unwrap_or(true) || header == "\r\n" {
                            break;
                        }
                    }
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = files.lock().ok().and_then(|f| f.get(&path).cloned());
                    let mut out = &stream;
                    let _ = match body {
                        Some(body) => out
                            .write_all(format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())
                            .and_then(|_| out.write_all(&body)),
                        None => out.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
                    };
                });
            }
        });
        Ok(Server { files })
    }

    /// Publishes the machine's seed and returns the URL for `ds=nocloud;s=`.
    pub fn publish(&self, lab: &Lab, m: &Machine) -> Result<String> {
        let mut files = self.files.lock().map_err(|_| anyhow::anyhow!("seed lock poisoned"))?;
        files.insert(format!("/{}/meta-data", m.name), meta_data(m).into_bytes());
        files.insert(format!("/{}/user-data", m.name), user_data(lab, m)?.into_bytes());
        files.insert(format!("/{}/vendor-data", m.name), Vec::new());
        Ok(format!("http://10.0.2.2:{PORT}/{}/", m.name))
    }
}

fn meta_data(m: &Machine) -> String {
    format!("instance-id: rackhand-lab-{}\nlocal-hostname: {}\n", m.name, m.name)
}

pub(crate) fn user_data(lab: &Lab, m: &Machine) -> Result<String> {
    let key = qemu::public_key()?;
    let alpine = m.image.starts_with("alpine");
    let site_nic = std::fs::read(workspace_root().join("lab/provision/site-nic.sh"))?;
    let mut runcmd = String::new();
    for (i, nic) in m.nics.iter().enumerate() {
        let prefix = lab.sites[&nic.site].prefix_len();
        runcmd.push_str(&format!(
            "  - [sh, /usr/local/sbin/rackhand-lab-site-nic, \"{}\", \"{}\", \"{prefix}\"]\n",
            qemu::mac(lab, m, i + 1),
            nic.address
        ));
    }
    let (groups, shell, packages) =
        if alpine { ("wheel", "/bin/ash", "packages: [sudo, bash, iputils]\n") } else { ("sudo", "/bin/bash", "") };
    if alpine {
        // Alpine's sshd refuses accounts locked with `!`; `*` means "no password" without locking key logins.
        runcmd.push_str("  - [sed, -i, 's/^lab:!/lab:*/', /etc/shadow]\n");
    }
    Ok(format!(
        "#cloud-config
hostname: {name}
users:
  - name: lab
    groups: [{groups}]
    sudo: \"ALL=(ALL) NOPASSWD:ALL\"
    shell: {shell}
    lock_passwd: true
    ssh_authorized_keys:
      - {key}
ssh_pwauth: false
disable_root: true
{packages}write_files:
  - path: /usr/local/sbin/rackhand-lab-site-nic
    permissions: \"0755\"
    encoding: b64
    content: {nic_script}
runcmd:
{runcmd}  - [touch, /var/lib/rackhand-lab-ready]
",
        name = m.name,
        nic_script = base64(&site_nic),
    ))
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_known_values() {
        assert_eq!(super::base64(b"Man"), "TWFu");
        assert_eq!(super::base64(b"Ma"), "TWE=");
        assert_eq!(super::base64(b"M"), "TQ==");
    }
}
