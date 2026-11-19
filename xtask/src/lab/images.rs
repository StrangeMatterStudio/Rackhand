//! `lab/images.toml`: pinned base images, fetched and checked (plan L1).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};

use super::lab_dir;
use crate::vm::run_checked;
use crate::workspace_root;

#[derive(Debug, Clone, Deserialize)]
pub struct Image {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha512: Option<String>,
}

#[derive(Deserialize)]
struct ImagesFile {
    image: Vec<Image>,
}

pub fn load() -> Result<Vec<Image>> {
    let path = workspace_root().join("lab/images.toml");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(toml::from_str::<ImagesFile>(&text).context("parsing lab/images.toml")?.image)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Image {
    pub fn path(&self) -> PathBuf {
        lab_dir().join("images").join(format!("{}.qcow2", self.name))
    }

    /// Checks the file against the pinned hash; deletes it and fails on a mismatch.
    pub fn verify(&self, path: &Path) -> Result<()> {
        let mut file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut s256 = Sha256::new();
        let mut s512 = Sha512::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if self.sha256.is_some() {
                s256.update(&buf[..n]);
            }
            if self.sha512.is_some() {
                s512.update(&buf[..n]);
            }
        }
        let (kind, expected, actual) = match (&self.sha512, &self.sha256) {
            (Some(e), _) => ("SHA-512", e, hex(&s512.finalize())),
            (None, Some(e)) => ("SHA-256", e, hex(&s256.finalize())),
            (None, None) => bail!("image `{}` has no pinned hash", self.name),
        };
        if &actual != expected {
            std::fs::remove_file(path)?;
            bail!("{kind} mismatch for {} ({}): expected {expected}, got {actual}; deleted", self.name, path.display());
        }
        Ok(())
    }

    /// Downloads the image if it isn't cached, then checks it.
    pub fn fetch(&self) -> Result<PathBuf> {
        let path = self.path();
        let stamp = path.with_extension("verified");
        if path.exists() && stamp.exists() {
            return Ok(path);
        }
        std::fs::create_dir_all(path.parent().context("image dir")?)?;
        if !path.exists() {
            println!("fetching {}", self.url);
            let partial = path.with_extension("part");
            run_checked(Command::new("curl").args(["-fsSL", "--retry", "3", "-o"]).arg(&partial).arg(&self.url))?;
            std::fs::rename(&partial, &path)?;
        }
        self.verify(&path)?;
        std::fs::write(&stamp, b"ok")?;
        println!("{} verified", self.name);
        Ok(path)
    }
}

pub fn find(name: &str) -> Result<Image> {
    load()?.into_iter().find(|i| i.name == name).with_context(|| format!("no image `{name}` in lab/images.toml"))
}

pub fn fetch_all() -> Result<()> {
    for image in load()? {
        image.fetch()?;
    }
    Ok(())
}
