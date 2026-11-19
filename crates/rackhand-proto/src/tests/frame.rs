use prost::Message;

use crate::frame::{FrameError, MAX_FRAME, read_frame, write_frame};
use crate::samples;

#[test]
fn round_trip_every_message_type() {
    for (name, bytes, decode) in samples::all() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &bytes).unwrap();
        assert_eq!(&wire[..4], &(bytes.len() as u32).to_be_bytes(), "{name}: length prefix");
        let mut cursor = std::io::Cursor::new(wire);
        let body = read_frame(&mut cursor).unwrap();
        assert_eq!(body, bytes, "{name}: body");
        assert!(decode(&body), "{name}: decodes back to an equal message");
    }
    assert!(samples::all().len() >= 20, "a sample for every message type");
}

#[test]
fn frame_over_4_mib_is_rejected_before_allocation() {
    let mut wire = ((MAX_FRAME as u32) + 1).to_be_bytes().to_vec();
    wire.extend_from_slice(b"short body");
    let mut cursor = std::io::Cursor::new(wire);
    match read_frame(&mut cursor) {
        Err(FrameError::TooLarge(n)) => assert_eq!(n, MAX_FRAME + 1),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert_eq!(cursor.position(), 4, "the body was not read");
    let ok = crate::probe::Ack { epoch: 1, ranges: vec![] }.encode_to_vec();
    let mut wire = Vec::new();
    write_frame(&mut wire, &ok).unwrap();
    assert!(read_frame(&mut std::io::Cursor::new(wire)).is_ok());
}
