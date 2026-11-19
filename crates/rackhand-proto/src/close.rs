//! Application close codes shared by every QUIC contract (7.3).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CloseCode {
    UnknownPeer = 0x10,
    IdentityMismatch = 0x11,
    UnsupportedVersion = 0x12,
    Revoked = 0x13,
    RateLimited = 0x14,
    FrameTooLarge = 0x15,
}

impl CloseCode {
    pub fn from_code(code: u64) -> Option<CloseCode> {
        Some(match code {
            0x10 => CloseCode::UnknownPeer,
            0x11 => CloseCode::IdentityMismatch,
            0x12 => CloseCode::UnsupportedVersion,
            0x13 => CloseCode::Revoked,
            0x14 => CloseCode::RateLimited,
            0x15 => CloseCode::FrameTooLarge,
            _ => return None,
        })
    }

    pub fn reason(self) -> &'static [u8] {
        match self {
            CloseCode::UnknownPeer => b"unknown peer",
            CloseCode::IdentityMismatch => b"identity mismatch",
            CloseCode::UnsupportedVersion => b"unsupported version",
            CloseCode::Revoked => b"revoked",
            CloseCode::RateLimited => b"rate limited",
            CloseCode::FrameTooLarge => b"frame too large",
        }
    }
}

impl std::fmt::Display for CloseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02x})", String::from_utf8_lossy(self.reason()), *self as u32)
    }
}

impl std::error::Error for CloseCode {}
