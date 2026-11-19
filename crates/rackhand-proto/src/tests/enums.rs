use prost::Message;

use crate::join::{JoinError, JoinFailed, JoinResponse, join_response};
use crate::known_or_unsupported;

#[test]
fn unknown_enum_value_maps_to_unsupported() {
    // A newer hub sends a JoinError value this build doesn't know.
    let wire = JoinResponse { kind: Some(join_response::Kind::Error(JoinFailed { code: 99, message: "new".into() })) }
        .encode_to_vec();
    let decoded = JoinResponse::decode(wire.as_slice()).unwrap();
    let Some(join_response::Kind::Error(failed)) = decoded.kind else { panic!("not an error") };
    assert_eq!(known_or_unsupported(failed.code, JoinError::Unsupported), JoinError::Unsupported);
    assert_eq!(known_or_unsupported(JoinError::Used as i32, JoinError::Unsupported), JoinError::Used);
}
