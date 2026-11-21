# Test release keys

Test only. These keys are public on purpose and are never valid for a real release: a release build pins the keys in
`crates/rackhand-release/keys/`, and only a build with the `test-keys` feature pins these.

- `test-current.seed` and `test-standby.seed`: the Ed25519 seeds (hex), so tests can sign artifacts.
- `test-current.pub` and `test-standby.pub`: their minisign public key files (key ids `0101010101010101` and
  `0202020202020202`).
- `test-other.seed`: a key that is pinned nowhere.
