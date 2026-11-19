use crate::close::CloseCode;
use crate::zstd::{MAX_DECOMPRESSED, compress, decompress_bounded};

#[test]
fn decompression_past_16_mib_fails_with_0x15() {
    let bomb = compress(&vec![0u8; MAX_DECOMPRESSED + 1]).unwrap();
    assert!(bomb.len() < 4 * 1024 * 1024, "the frame itself is small");
    let err = decompress_bounded(&bomb).unwrap_err();
    assert_eq!(err, CloseCode::FrameTooLarge);
    assert_eq!(err as u32, 0x15);

    let fine = compress(&vec![7u8; MAX_DECOMPRESSED]).unwrap();
    assert_eq!(decompress_bounded(&fine).unwrap().len(), MAX_DECOMPRESSED);
}
