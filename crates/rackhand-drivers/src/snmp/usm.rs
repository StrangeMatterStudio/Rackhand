//! SNMPv3's user-based security (RFC 3414, 3826): password to key, the key localized to the agent's engine,
//! HMAC-SHA-96 authentication, AES-128-CFB privacy, and the v3 message around a scoped PDU.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use super::ber;

pub const AUTH: u8 = 0x01;
pub const PRIV: u8 = 0x02;
pub const REPORTABLE: u8 = 0x04;
const AUTH_LEN: usize = 12;

/// RFC 3414 A.2.2: SHA-1 over the password repeated to 1 MB, then localized to `engine`.
pub fn localized_key(password: &str, engine: &[u8]) -> [u8; 20] {
    let p = password.as_bytes();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    let mut block = [0u8; 64];
    let mut at = 0usize;
    for _ in 0..(1_048_576 / 64) {
        for b in block.iter_mut() {
            *b = p[at % p.len()];
            at += 1;
        }
        ctx.update(&block);
    }
    let ku = ctx.finish();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(ku.as_ref());
    ctx.update(engine);
    ctx.update(ku.as_ref());
    let mut out = [0u8; 20];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

pub fn hmac_sha96(key: &[u8; 20], msg: &[u8]) -> [u8; AUTH_LEN] {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = ring::hmac::sign(&k, msg);
    let mut out = [0u8; AUTH_LEN];
    out.copy_from_slice(&tag.as_ref()[..AUTH_LEN]);
    out
}

/// AES-128 in CFB mode (128-bit feedback), as RFC 3826 uses it; `decrypt` turns it around.
pub fn aes_cfb(key: &[u8; 20], boots: u32, time: u32, salt: &[u8; 8], data: &[u8], decrypt: bool) -> Vec<u8> {
    let cipher = aes::Aes128::new(GenericArray::from_slice(&key[..16]));
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(salt);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&iv);
        cipher.encrypt_block(&mut block);
        let mut next = [0u8; 16];
        for (i, b) in chunk.iter().enumerate() {
            let c = b ^ block[i];
            out.push(c);
            next[i] = if decrypt { *b } else { c };
        }
        iv = next;
    }
    out
}

/// The security parameters of a v3 message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Params {
    pub engine: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub user: String,
    pub auth: Vec<u8>,
    pub salt: Vec<u8>,
}

fn params(p: &Params) -> Vec<u8> {
    ber::seq(&[
        ber::octets(&p.engine),
        ber::int(p.boots.into()),
        ber::int(p.time.into()),
        ber::octets(p.user.as_bytes()),
        ber::octets(&p.auth),
        ber::octets(&p.salt),
    ])
}

/// A v3 message: `data` is the scoped PDU's encoding (plain) or its encryption (an octet string, `PRIV`).
pub fn message(msg_id: i64, flags: u8, p: &Params, data: &[u8]) -> Vec<u8> {
    let header = ber::seq(&[ber::int(msg_id), ber::int(65_507), ber::octets(&[flags]), ber::int(3)]);
    ber::seq(&[ber::int(3), header, ber::octets(&params(p)), data.to_vec()])
}

/// The message signed: built with 12 zero bytes for the authentication parameter, then with the HMAC over that.
pub fn signed(msg_id: i64, flags: u8, p: &Params, data: &[u8], key: &[u8; 20]) -> Vec<u8> {
    let mut p = p.clone();
    p.auth = vec![0; AUTH_LEN];
    let unsigned = message(msg_id, flags, &p, data);
    p.auth = hmac_sha96(key, &unsigned).to_vec();
    message(msg_id, flags, &p, data)
}

/// A v3 message taken apart: id, flags, security parameters, the msgData TLV (tag and body).
#[derive(Debug)]
pub struct Parsed {
    pub msg_id: i64,
    pub flags: u8,
    pub params: Params,
    pub data_tag: u8,
    pub data: Vec<u8>,
}

pub fn parse(msg: &[u8]) -> Result<Parsed, String> {
    let mut outer = ber::Reader::new(msg);
    let mut m = ber::Reader::new(outer.expect(ber::SEQUENCE)?);
    if m.int()? != 3 {
        return Err("not SNMPv3".into());
    }
    let mut h = ber::Reader::new(m.expect(ber::SEQUENCE)?);
    let msg_id = h.int()?;
    let _max = h.int()?;
    let flags = *h.octets()?.first().ok_or("no flags")?;
    let mut sp = ber::Reader::new(m.octets()?);
    let mut s = ber::Reader::new(sp.expect(ber::SEQUENCE)?);
    let params = Params {
        engine: s.octets()?.to_vec(),
        boots: s.int()? as u32,
        time: s.int()? as u32,
        user: String::from_utf8_lossy(s.octets()?).into_owned(),
        auth: s.octets()?.to_vec(),
        salt: s.octets()?.to_vec(),
    };
    let (data_tag, body) = m.next_tlv()?;
    // a plaintext scoped PDU whole (as `parse_scoped` reads it); an encrypted one as its ciphertext
    let data = if data_tag == ber::SEQUENCE { ber::tlv(ber::SEQUENCE, body) } else { body.to_vec() };
    Ok(Parsed { msg_id, flags, params, data_tag, data })
}

/// Whether `msg` carries a valid HMAC for `key` (the HMAC checked with the parameter zeroed).
pub fn authentic(msg: &[u8], p: &Parsed, key: &[u8; 20]) -> bool {
    if p.params.auth.len() != AUTH_LEN {
        return false;
    }
    let Some(at) = msg.windows(AUTH_LEN).position(|w| w == p.params.auth.as_slice()) else { return false };
    let mut zeroed = msg.to_vec();
    zeroed[at..at + AUTH_LEN].fill(0);
    // compared without stopping at the first difference
    hmac_sha96(key, &zeroed).iter().zip(&p.params.auth).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// A scoped PDU: context engine, context name (empty), the PDU.
pub fn scoped(engine: &[u8], pdu: &ber::Pdu) -> Vec<u8> {
    ber::seq(&[ber::octets(engine), ber::octets(b""), ber::pdu(pdu)])
}

pub fn parse_scoped(body: &[u8]) -> Result<ber::Pdu, String> {
    let mut r = ber::Reader::new(body);
    let mut s = ber::Reader::new(r.expect(ber::SEQUENCE)?);
    let _engine = s.octets()?;
    let _context = s.octets()?;
    let (kind, pdu) = s.next_tlv()?;
    ber::parse_pdu(kind, pdu)
}
