//! The BER subset SNMP uses (RFC 3416, 3412, 3414): integers, octet strings, null, OIDs, sequences, the application
//! types (Counter32, Gauge32, TimeTicks, Counter64, IpAddress), the "no such" markers, and the read PDUs.

pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const IP_ADDRESS: u8 = 0x40;
pub const COUNTER32: u8 = 0x41;
pub const GAUGE32: u8 = 0x42;
pub const TIMETICKS: u8 = 0x43;
pub const COUNTER64: u8 = 0x46;
pub const NO_SUCH_OBJECT: u8 = 0x80;
pub const NO_SUCH_INSTANCE: u8 = 0x81;
pub const END_OF_MIB_VIEW: u8 = 0x82;
pub const GET: u8 = 0xA0;
pub const GET_NEXT: u8 = 0xA1;
pub const RESPONSE: u8 = 0xA2;
pub const REPORT: u8 = 0xA8;

/// A value in a varbind.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    /// Counter32, Gauge32, TimeTicks and Counter64, with their tag.
    Unsigned(u8, u64),
    Ip([u8; 4]),
    /// noSuchObject, noSuchInstance, endOfMibView.
    Missing(u8),
}

impl Value {
    pub fn number(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Unsigned(_, u) => Some(*u as f64),
            _ => None,
        }
    }
}

fn len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

pub fn int(i: i64) -> Vec<u8> {
    let bytes = i.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(INTEGER, &bytes[start..])
}

fn unsigned(tag: u8, u: u64) -> Vec<u8> {
    let bytes = u.to_be_bytes();
    let mut body: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if body.is_empty() || body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(tag, &body)
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

pub fn oid(o: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if o.len() >= 2 {
        body.push((o[0] * 40 + o[1]) as u8);
        for &n in &o[2..] {
            let mut stack = vec![(n & 0x7f) as u8];
            let mut n = n >> 7;
            while n > 0 {
                stack.push(0x80 | (n & 0x7f) as u8);
                n >>= 7;
            }
            body.extend(stack.iter().rev());
        }
    }
    tlv(OID, &body)
}

pub fn value(v: &Value) -> Vec<u8> {
    match v {
        Value::Int(i) => int(*i),
        Value::Bytes(b) => octets(b),
        Value::Null => tlv(NULL, &[]),
        Value::Oid(o) => oid(o),
        Value::Unsigned(tag, u) => unsigned(*tag, *u),
        Value::Ip(ip) => tlv(IP_ADDRESS, ip),
        Value::Missing(tag) => tlv(*tag, &[]),
    }
}

/// A PDU: `kind` (`GET`, `GET_NEXT`, `RESPONSE`, `REPORT`), request id, error status, and varbinds.
#[derive(Debug, Clone, PartialEq)]
pub struct Pdu {
    pub kind: u8,
    pub request_id: i64,
    pub error_status: i64,
    pub varbinds: Vec<(Vec<u32>, Value)>,
}

pub fn pdu(p: &Pdu) -> Vec<u8> {
    let binds: Vec<Vec<u8>> = p.varbinds.iter().map(|(o, v)| seq(&[oid(o), value(v)])).collect();
    tlv(p.kind, &[int(p.request_id), int(p.error_status), int(0), seq(&binds)].concat())
}

/// A reader over one TLV's body.
#[derive(Debug)]
pub struct Reader<'a> {
    pub buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next TLV: its tag and body.
    pub fn next_tlv(&mut self) -> Result<(u8, &'a [u8]), String> {
        let tag = *self.buf.first().ok_or("a short message")?;
        let first = *self.buf.get(1).ok_or("a short message")?;
        let (n, head) = if first & 0x80 == 0 {
            (first as usize, 2)
        } else {
            let k = (first & 0x7f) as usize;
            if k == 0 || k > 4 {
                return Err("a length SNMP doesn't use".into());
            }
            let bytes = self.buf.get(2..2 + k).ok_or("a short message")?;
            (bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), 2 + k)
        };
        let body = self.buf.get(head..head + n).ok_or("a short message")?;
        self.buf = &self.buf[head + n..];
        Ok((tag, body))
    }

    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], String> {
        let (t, body) = self.next_tlv()?;
        if t != tag {
            return Err(format!("expected tag {tag:#x}, got {t:#x}"));
        }
        Ok(body)
    }

    pub fn int(&mut self) -> Result<i64, String> {
        let body = self.expect(INTEGER)?;
        if body.is_empty() || body.len() > 8 {
            return Err("an integer SNMP doesn't use".into());
        }
        let mut v: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
        for b in body {
            v = (v << 8) | *b as i64;
        }
        Ok(v)
    }

    pub fn octets(&mut self) -> Result<&'a [u8], String> {
        self.expect(OCTET_STRING)
    }
}

pub fn parse_oid(body: &[u8]) -> Result<Vec<u32>, String> {
    let first = *body.first().ok_or("an empty OID")?;
    let mut out = vec![(first / 40) as u32, (first % 40) as u32];
    let mut n: u32 = 0;
    for b in &body[1..] {
        n = n.checked_mul(128).ok_or("an OID too large")? | (*b & 0x7f) as u32;
        if b & 0x80 == 0 {
            out.push(n);
            n = 0;
        }
    }
    Ok(out)
}

pub fn parse_value(tag: u8, body: &[u8]) -> Result<Value, String> {
    Ok(match tag {
        INTEGER => Reader::new(&tlv(INTEGER, body)).int().map(Value::Int)?,
        OCTET_STRING => Value::Bytes(body.to_vec()),
        NULL => Value::Null,
        OID => Value::Oid(parse_oid(body)?),
        COUNTER32 | GAUGE32 | TIMETICKS | COUNTER64 => {
            if body.len() > 9 {
                return Err("a counter SNMP doesn't use".into());
            }
            Value::Unsigned(tag, body.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
        }
        IP_ADDRESS => Value::Ip(body.try_into().map_err(|_| "an address that isn't 4 bytes")?),
        NO_SUCH_OBJECT | NO_SUCH_INSTANCE | END_OF_MIB_VIEW => Value::Missing(tag),
        other => return Err(format!("a value of type {other:#x}")),
    })
}

/// A PDU from its tag and body.
pub fn parse_pdu(kind: u8, body: &[u8]) -> Result<Pdu, String> {
    let mut r = Reader::new(body);
    let request_id = r.int()?;
    let error_status = r.int()?;
    let _error_index = r.int()?;
    let mut binds = Reader::new(r.expect(SEQUENCE)?);
    let mut varbinds = Vec::new();
    while !binds.is_empty() {
        let mut vb = Reader::new(binds.expect(SEQUENCE)?);
        let o = parse_oid(vb.expect(OID)?)?;
        let (tag, v) = vb.next_tlv()?;
        varbinds.push((o, parse_value(tag, v)?));
    }
    Ok(Pdu { kind, request_id, error_status, varbinds })
}

pub fn dotted(o: &[u32]) -> String {
    o.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

pub fn from_dotted(s: &str) -> Option<Vec<u32>> {
    let parts: Option<Vec<u32>> = s.trim_start_matches('.').split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| p.len() >= 2 && p[0] <= 2 && p[1] < 40)
}
