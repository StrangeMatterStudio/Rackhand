//! zstd for reports and replay batches, with a hard 16 MB limit on decompressed size (7.3, E53).

use std::io::Read;

use crate::close::CloseCode;

pub const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

pub fn compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    ::zstd::bulk::compress(data, 3)
}

/// Decompresses `data`, failing with [`CloseCode::FrameTooLarge`] (`0x15`) as soon as the output would pass 16 MB or
/// the input isn't valid zstd.
pub fn decompress_bounded(data: &[u8]) -> Result<Vec<u8>, CloseCode> {
    let decoder = ::zstd::stream::read::Decoder::new(data).map_err(|_| CloseCode::FrameTooLarge)?;
    let mut out = Vec::new();
    let read = decoder.take(MAX_DECOMPRESSED as u64 + 1).read_to_end(&mut out).map_err(|_| CloseCode::FrameTooLarge)?;
    if read > MAX_DECOMPRESSED {
        return Err(CloseCode::FrameTooLarge);
    }
    Ok(out)
}
