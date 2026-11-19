//! SSH to managed machines (7.2, SSH; 7.3.7): one connection per command and identity, POSIX quoting, host keys
//! pinned from the join. Owns `ssh_host_keys`.

pub mod client;
pub mod hostkeys;
pub mod keys;
pub mod quote;

#[cfg(test)]
mod tests;
