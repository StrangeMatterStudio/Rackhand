//! Peer hubs, linked pairwise with an invite (7.3.1, 7.3.4, 7.8.1).

use super::tokens::{self, Bound, Token, TokenKind};
use super::{Registry, RegistryError};
use rackhand_store::WriteCmd;

/// Site names follow the `sites.name` rule: 1 to 32 of `a-z`, `0-9` and `-`.
pub(crate) fn valid_site_name(name: &str) -> bool {
    (1..=32).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Registry {
    /// A 24-hour peer invite.
    pub async fn invite_peer(&self, created_by: &str, now_ms: i64) -> Result<Token, RegistryError> {
        let (token, row) = tokens::issue(TokenKind::Peer, None, &Bound::default(), created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![row])).await?;
        Ok(token)
    }

    /// Whether the name is this hub's own site, another local site, or a linked peer's.
    pub(crate) fn site_name_known(&self, name: &str) -> rusqlite::Result<bool> {
        self.db().readers().with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM sites WHERE name = ?1) OR EXISTS (SELECT 1 FROM peers WHERE site = ?1)",
                [name],
                |r| r.get(0),
            )
        })
    }
}
