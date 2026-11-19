//! Devices: a person's laptop or phone, joined with an invite bound to their user (7.3.12).

use super::tokens::{self, Bound, Token, TokenKind};
use super::{Registry, RegistryError};
use rackhand_store::WriteCmd;

impl Registry {
    /// A 24-hour invite for one of `user_id`'s devices.
    pub async fn invite_device(&self, user_id: &str, created_by: &str, now_ms: i64) -> Result<Token, RegistryError> {
        let bound = Bound { user_id: Some(user_id.into()), ..Bound::default() };
        let (token, row) = tokens::issue(TokenKind::Device, None, &bound, created_by, now_ms)?;
        self.db().writer().send(WriteCmd::Batch(vec![row])).await?;
        Ok(token)
    }

    pub(crate) fn user_name(&self, user_id: &str) -> rusqlite::Result<Option<String>> {
        use rusqlite::OptionalExtension;
        self.db().readers().with(|c| {
            c.query_row("SELECT name FROM users WHERE id = ?1 AND disabled_at IS NULL", [user_id], |r| r.get(0))
                .optional()
        })
    }
}
