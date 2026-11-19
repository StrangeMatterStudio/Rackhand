use std::os::unix::fs::PermissionsExt;

use crate::key::load_or_create;

#[test]
fn node_key_persists_with_mode_0600() {
    let dir = std::env::temp_dir().join(format!("rackhand-net-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("node.key");
    let first = load_or_create(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "node key mode");
    let again = load_or_create(&path).unwrap();
    assert_eq!(first.public(), again.public(), "the same id after a reload");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_or_create(&path).is_err(), "a key readable by others is refused");
    std::fs::remove_dir_all(&dir).unwrap();
}
