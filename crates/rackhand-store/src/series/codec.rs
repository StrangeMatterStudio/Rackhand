//! The chunk codec (7.4.1 chunk encoding, D109).
//!
//! A chunk is a format byte, the point count (LEB128), the column count (one byte) and a bit stream: the timestamps
//! (the first in 64 bits, then delta-of-delta), then each column behind a 2-bit tag. An integer column (a whole number
//! of its step) adds a 2-bit step and is coded with whichever of delta-of-delta, delta and Gorilla XOR is smallest. A
//! float column is coded with Gorilla XOR. Deltas use a bucket ladder of 1, 9, 12, 16, 25, 38 or 70 bits.

use super::bits::{BitReader, BitWriter};
use super::step::Step;

const FORMAT: u8 = 1;
/// Integers up to this magnitude are exact as f64, so the XOR coder may carry them.
const EXACT_IN_F64: u64 = 1 << 53;

#[derive(Debug, Clone, PartialEq)]
pub enum Column {
    /// Whole multiples of `step`.
    Int { step: Step, values: Vec<i64> },
    /// Values without a step, kept bit for bit.
    Float(Vec<f64>),
}

impl Column {
    /// The integer column when the metric has a step and every value has an integer at it, else a float column.
    pub fn from_values(step: Option<Step>, values: &[f64]) -> Column {
        if let Some(step) = step {
            let ints: Option<Vec<i64>> = values.iter().map(|&v| step.to_int(v)).collect();
            if let Some(values) = ints {
                return Column::Int { step, values };
            }
        }
        Column::Float(values.to_vec())
    }

    pub fn len(&self) -> usize {
        match self {
            Column::Int { values, .. } => values.len(),
            Column::Float(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_f64(&self) -> Vec<f64> {
        match self {
            Column::Int { step, values } => values.iter().map(|&v| step.to_f64(v)).collect(),
            Column::Float(values) => values.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub ts: Vec<i64>,
    pub cols: Vec<Column>,
}

/// How an integer column is coded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coder {
    DeltaOfDelta,
    Delta,
    Xor,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("unknown chunk format {0}")]
    Format(u8),
    #[error("chunk data ends early")]
    Truncated,
    #[error("chunk columns don't match its timestamps")]
    Shape,
}

const TAG_DOD: u64 = 0;
const TAG_DELTA: u64 = 1;
const TAG_XOR: u64 = 2;
const TAG_FLOAT: u64 = 3;

pub fn encode(chunk: &Chunk) -> Vec<u8> {
    encode_columns(chunk, best_int)
}

/// Encodes with the given coder for each integer column (for comparing coders).
pub fn encode_with(chunk: &Chunk, coders: &[Coder]) -> Vec<u8> {
    let mut i = 0;
    encode_columns(chunk, |values| {
        let coder = coders[i.min(coders.len() - 1)];
        i += 1;
        int_bits(values, coder).map(|w| (coder, w)).unwrap_or_else(|| best_int(values))
    })
}

/// The coder [`encode`] picks for an integer column.
pub fn coder_for(values: &[i64]) -> Coder {
    best_int(values).0
}

fn encode_columns(chunk: &Chunk, mut int_column: impl FnMut(&[i64]) -> (Coder, BitWriter)) -> Vec<u8> {
    let n = chunk.ts.len();
    let mut out = vec![FORMAT];
    leb128(&mut out, n as u64);
    out.push(chunk.cols.len() as u8);
    if n == 0 {
        return out;
    }
    let mut w = BitWriter::new();
    w.push(chunk.ts[0] as u64, 64);
    let mut prev_d = 0i64;
    for pair in chunk.ts.windows(2) {
        let d = pair[1].wrapping_sub(pair[0]);
        ladder(&mut w, d.wrapping_sub(prev_d));
        prev_d = d;
    }
    for col in &chunk.cols {
        match col {
            Column::Int { step, values } => {
                let (coder, body) = int_column(values);
                w.push(coder.tag(), 2);
                w.push(step.code(), 2);
                append(&mut w, body);
            }
            Column::Float(values) => {
                w.push(TAG_FLOAT, 2);
                xor(&mut w, values.iter().map(|v| v.to_bits()));
            }
        }
    }
    out.extend(w.into_bytes());
    out
}

impl Coder {
    fn tag(self) -> u64 {
        match self {
            Coder::DeltaOfDelta => TAG_DOD,
            Coder::Delta => TAG_DELTA,
            Coder::Xor => TAG_XOR,
        }
    }
}

/// The smallest coding of an integer column.
fn best_int(values: &[i64]) -> (Coder, BitWriter) {
    [Coder::DeltaOfDelta, Coder::Delta, Coder::Xor]
        .into_iter()
        .filter_map(|c| int_bits(values, c).map(|w| (c, w)))
        .min_by_key(|(_, w)| w.bit_len())
        .expect("delta coding always applies")
}

/// An integer column body, or `None` when the coder can't carry these values.
fn int_bits(values: &[i64], coder: Coder) -> Option<BitWriter> {
    let mut w = BitWriter::new();
    match coder {
        Coder::DeltaOfDelta | Coder::Delta => {
            w.push(values[0] as u64, 64);
            let mut prev_d = 0i64;
            for pair in values.windows(2) {
                let d = pair[1].wrapping_sub(pair[0]);
                ladder(&mut w, if coder == Coder::Delta { d } else { d.wrapping_sub(prev_d) });
                prev_d = d;
            }
        }
        Coder::Xor => {
            if values.iter().any(|v| v.unsigned_abs() > EXACT_IN_F64) {
                return None;
            }
            xor(&mut w, values.iter().map(|&v| (v as f64).to_bits()));
        }
    }
    Some(w)
}

pub fn decode(data: &[u8]) -> Result<Chunk, CodecError> {
    let (&format, rest) = data.split_first().ok_or(CodecError::Truncated)?;
    if format != FORMAT {
        return Err(CodecError::Format(format));
    }
    let (n, rest) = read_leb128(rest)?;
    let (&ncols, rest) = rest.split_first().ok_or(CodecError::Truncated)?;
    let n = usize::try_from(n).map_err(|_| CodecError::Shape)?;
    if n == 0 {
        return Ok(Chunk { ts: Vec::new(), cols: (0..ncols).map(|_| Column::Float(Vec::new())).collect() });
    }
    if n > rest.len() * 8 {
        return Err(CodecError::Shape);
    }
    let mut r = BitReader::new(rest);
    let mut ts = Vec::with_capacity(n);
    ts.push(take(&mut r, 64)? as i64);
    let mut prev_d = 0i64;
    for i in 1..n {
        let d = prev_d.wrapping_add(read_ladder(&mut r)?);
        ts.push(ts[i - 1].wrapping_add(d));
        prev_d = d;
    }
    let mut cols = Vec::with_capacity(ncols as usize);
    for _ in 0..ncols {
        let tag = take(&mut r, 2)?;
        if tag == TAG_FLOAT {
            cols.push(Column::Float(read_xor(&mut r, n)?.into_iter().map(f64::from_bits).collect()));
            continue;
        }
        let coder = tag;
        let step = Step::from_code(take(&mut r, 2)?);
        let values = match coder {
            TAG_XOR => read_xor(&mut r, n)?.into_iter().map(|b| f64::from_bits(b) as i64).collect(),
            TAG_DOD | TAG_DELTA => {
                let mut v = Vec::with_capacity(n);
                v.push(take(&mut r, 64)? as i64);
                let mut prev_d = 0i64;
                for i in 1..n {
                    let x = read_ladder(&mut r)?;
                    let d = if coder == TAG_DELTA { x } else { prev_d.wrapping_add(x) };
                    v.push(v[i - 1].wrapping_add(d));
                    prev_d = d;
                }
                v
            }
            _ => return Err(CodecError::Shape),
        };
        cols.push(Column::Int { step, values });
    }
    Ok(Chunk { ts, cols })
}

fn take(r: &mut BitReader, n: u32) -> Result<u64, CodecError> {
    r.read(n).ok_or(CodecError::Truncated)
}

fn append(w: &mut BitWriter, other: BitWriter) {
    let len = other.bit_len();
    let bytes = other.into_bytes();
    let full = len / 8;
    for &b in &bytes[..full] {
        w.push(b as u64, 8);
    }
    let rest = (len % 8) as u32;
    if rest > 0 {
        w.push((bytes[full] >> (8 - rest)) as u64, rest);
    }
}

fn zigzag(x: i64) -> u64 {
    ((x << 1) ^ (x >> 63)) as u64
}

fn unzigzag(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}

/// (prefix, prefix bits, payload bits) for each bucket after the 1-bit zero.
const BUCKETS: [(u64, u32, u32); 6] =
    [(0b10, 2, 7), (0b110, 3, 9), (0b1110, 4, 12), (0b11110, 5, 20), (0b111110, 6, 32), (0b111111, 6, 64)];

fn ladder(w: &mut BitWriter, x: i64) {
    if x == 0 {
        w.push(0, 1);
        return;
    }
    let z = zigzag(x);
    for (prefix, plen, bits) in BUCKETS {
        if bits == 64 || z < 1u64 << bits {
            w.push(prefix, plen);
            w.push(z, bits);
            return;
        }
    }
}

fn read_ladder(r: &mut BitReader) -> Result<i64, CodecError> {
    let mut ones = 0;
    while ones < 6 {
        if !r.bit().ok_or(CodecError::Truncated)? {
            break;
        }
        ones += 1;
    }
    if ones == 0 {
        return Ok(0);
    }
    let bits = BUCKETS[ones - 1].2;
    Ok(unzigzag(take(r, bits)?))
}

/// Gorilla XOR coding of 64-bit patterns.
fn xor(w: &mut BitWriter, mut values: impl Iterator<Item = u64>) {
    let Some(first) = values.next() else { return };
    w.push(first, 64);
    let mut prev = first;
    let (mut lead, mut trail) = (u32::MAX, 0u32);
    for v in values {
        let x = v ^ prev;
        prev = v;
        if x == 0 {
            w.push(0, 1);
            continue;
        }
        let l = x.leading_zeros().min(31);
        let t = x.trailing_zeros();
        if lead != u32::MAX && l >= lead && t >= trail {
            w.push(0b10, 2);
            w.push(x >> trail, 64 - lead - trail);
        } else {
            lead = l;
            trail = t;
            let sig = 64 - l - t;
            w.push(0b11, 2);
            w.push(l as u64, 5);
            w.push((sig - 1) as u64, 6);
            w.push(x >> t, sig);
        }
    }
}

fn read_xor(r: &mut BitReader, n: usize) -> Result<Vec<u64>, CodecError> {
    let mut out = Vec::with_capacity(n);
    let mut prev = take(r, 64)?;
    out.push(prev);
    let (mut lead, mut trail) = (0u32, 0u32);
    for _ in 1..n {
        if take(r, 1)? == 1 {
            if take(r, 1)? == 1 {
                lead = take(r, 5)? as u32;
                let sig = take(r, 6)? as u32 + 1;
                if lead + sig > 64 {
                    return Err(CodecError::Shape);
                }
                trail = 64 - lead - sig;
            }
            prev ^= take(r, 64 - lead - trail)? << trail;
        }
        out.push(prev);
    }
    Ok(out)
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_leb128(data: &[u8]) -> Result<(u64, &[u8]), CodecError> {
    let mut v = 0u64;
    for (i, &b) in data.iter().enumerate().take(10) {
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((v, &data[i + 1..]));
        }
    }
    Err(CodecError::Truncated)
}
