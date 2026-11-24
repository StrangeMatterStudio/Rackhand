//! The hub's SSH keys (7.3.7): Ed25519, generated at bootstrap and held in the Vault; installed on machines with
//! `from="<hub addresses>"` and no forwarding.

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{PrivateKey, PublicKey};

use crate::vault::{Secret, Vault, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// `rackhand`: routine runbooks through the command wrapper.
    Automation,
    /// `rackhand-ai`: the assistant's account.
    Assistant,
}

impl Identity {
    pub fn user(self) -> &'static str {
        match self {
            Identity::Automation => "rackhand",
            Identity::Assistant => "rackhand-ai",
        }
    }

    fn vault_name(self) -> &'static str {
        match self {
            Identity::Automation => "ssh.automation",
            Identity::Assistant => "ssh.assistant",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
    #[error("key encoding: {0}")]
    Encoding(String),
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// A new Ed25519 key pair with a comment.
pub fn generate_ed25519(comment: &str) -> Result<(PrivateKey, PublicKey), KeyError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let pair = Ed25519Keypair::from_seed(&seed);
    let private =
        PrivateKey::new(KeypairData::Ed25519(pair), comment).map_err(|e| KeyError::Encoding(e.to_string()))?;
    let public = private.public_key().clone();
    Ok((private, public))
}

/// The Vault names of a machine's own key for `id`, and of the one made for its next rotation.
fn machine_name(id: Identity, machine: &str) -> String {
    format!("{}.machine.{machine}", id.vault_name())
}

fn next_name(id: Identity, machine: &str) -> String {
    format!("{}.next", machine_name(id, machine))
}

/// A key kept under `name`; none when nothing is stored there (or what is stored is empty).
fn stored(vault: &Vault, name: &str) -> Result<Option<PrivateKey>, KeyError> {
    let Ok(secret) = vault.get(name) else { return Ok(None) };
    let pem = String::from_utf8_lossy(secret.expose()).into_owned();
    if pem.trim().is_empty() {
        return Ok(None);
    }
    PrivateKey::from_openssh(&pem).map(Some).map_err(|e| KeyError::Encoding(e.to_string()))
}

async fn store(vault: &Vault, name: &str, key: &PrivateKey) -> Result<(), KeyError> {
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| KeyError::Encoding(e.to_string()))?;
    Ok(vault.put(name, &Secret::from(pem.as_str())).await?)
}

/// The key the hub uses for `id` on `machine`: the machine's own, once a rotation gave it one, else the hub's.
pub async fn load_for(vault: &Vault, id: Identity, machine: &str) -> Result<PrivateKey, KeyError> {
    match stored(vault, &machine_name(id, machine))? {
        Some(key) => Ok(key),
        None => load_or_create(vault, id).await,
    }
}

/// The key a rotation of `machine`'s key moves to: made the first time and kept until it is committed, so an attempt
/// that stopped halfway is taken up again with the same key. It changes nothing by itself.
pub async fn next_for(vault: &Vault, id: Identity, machine: &str) -> Result<PrivateKey, KeyError> {
    if let Some(key) = stored(vault, &next_name(id, machine))? {
        return Ok(key);
    }
    let (private, _) = generate_ed25519(id.user())?;
    store(vault, &next_name(id, machine), &private).await?;
    Ok(private)
}

/// Makes the pending key the machine's own, once the machine accepts it.
pub async fn commit_next(vault: &Vault, id: Identity, machine: &str) -> Result<(), KeyError> {
    let Some(next) = stored(vault, &next_name(id, machine))? else {
        return Err(KeyError::Encoding("no key is waiting to be used".into()));
    };
    store(vault, &machine_name(id, machine), &next).await?;
    Ok(vault.put(&next_name(id, machine), &Secret::from("")).await?)
}

/// The identity's private key from the Vault, generated and stored the first time.
pub async fn load_or_create(vault: &Vault, id: Identity) -> Result<PrivateKey, KeyError> {
    if let Ok(secret) = vault.get(id.vault_name()) {
        let pem = String::from_utf8_lossy(secret.expose()).into_owned();
        return PrivateKey::from_openssh(&pem).map_err(|e| KeyError::Encoding(e.to_string()));
    }
    let (private, _) = generate_ed25519(id.user())?;
    let pem =
        private.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| KeyError::Encoding(e.to_string()))?;
    vault.put(id.vault_name(), &Secret::from(pem.as_str())).await?;
    Ok(private)
}

/// The `authorized_keys` line for a machine: the key, limited to the hub's addresses and without forwarding.
pub fn authorized_keys_line(key: &PublicKey, from: &[String]) -> Result<String, KeyError> {
    let openssh = key.to_openssh().map_err(|e| KeyError::Encoding(e.to_string()))?;
    Ok(format!("from=\"{}\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding {openssh}", from.join(",")))
}
