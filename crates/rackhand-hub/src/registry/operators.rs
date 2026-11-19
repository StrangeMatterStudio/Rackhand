//! Operator hosts, joined with an invite (7.3.5, 7.3.12).

use super::tokens::{self, Bound, Token, TokenKind};
use super::{Registry, RegistryError};
use rackhand_store::WriteCmd;

impl Registry {
    /// A 24-hour operator invite.
    pub async fn invite_operator(&self, created_by: &str, now_ms: i64) -> Result<Token, RegistryError> {
        let (token, row) = tokens::issue(TokenKind::Operator, None, &Bound::default(), created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![row])).await?;
        Ok(token)
    }
}
