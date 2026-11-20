//! Bit-level writer and reader for the chunk codec, most significant bit first.

#[derive(Debug, Default)]
pub struct BitWriter {
    buf: Vec<u8>,
    /// Bits used in the last byte (8 when it is full or there is none).
    used: u32,
}

impl BitWriter {
    pub fn new() -> BitWriter {
        BitWriter { buf: Vec::new(), used: 8 }
    }

    /// Writes the low `n` bits of `value` (n at most 64).
    pub fn push(&mut self, value: u64, n: u32) {
        let mut left = n;
        while left > 0 {
            if self.used == 8 {
                self.buf.push(0);
                self.used = 0;
            }
            let room = 8 - self.used;
            let take = room.min(left);
            let shift = left - take;
            let bits = ((value >> shift) & ((1u64 << take) - 1)) as u8;
            let last = self.buf.last_mut().expect("a byte was pushed");
            *last |= bits << (room - take);
            self.used += take;
            left -= take;
        }
    }

    pub fn bit_len(&self) -> usize {
        if self.buf.is_empty() { 0 } else { (self.buf.len() - 1) * 8 + self.used as usize }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug)]
pub struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> BitReader<'a> {
        BitReader { buf, pos: 0 }
    }

    /// Reads `n` bits (n at most 64), or `None` past the end.
    pub fn read(&mut self, n: u32) -> Option<u64> {
        if self.pos + n as usize > self.buf.len() * 8 {
            return None;
        }
        let mut v = 0u64;
        let mut left = n;
        while left > 0 {
            let byte = self.buf[self.pos / 8];
            let offset = (self.pos % 8) as u32;
            let room = 8 - offset;
            let take = room.min(left);
            let bits = (byte >> (room - take)) & ((1u16 << take) - 1) as u8;
            v = (v << take) | bits as u64;
            self.pos += take as usize;
            left -= take;
        }
        Some(v)
    }

    pub fn bit(&mut self) -> Option<bool> {
        self.read(1).map(|b| b == 1)
    }
}
