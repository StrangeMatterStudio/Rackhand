# Signing a release

Design: section 13 (release signing, D90), 5.2 (supply chain), E64 and AC67 (the standby key). This is the procedure the
maintainer follows on a machine that is **not a CI runner**. No CI job, workflow or run step ever holds a signing key
(`cargo xtask ci-guard` checks that `release.yml` names no secret), and nothing in this repository signs for you: CI builds
the artifacts, you rebuild them, check that they are the same bytes, and sign them.

## The keys

Every binary and installer pins two public keys: the **current** key and a **standby** key whose private half is stored
separately and used for nothing else. They are minisign keys (Ed25519).

Create them once, offline, before the first release:

```sh
minisign -G -p current.pub -s current.key     # protect current.key with a passphrase; keep it offline
minisign -G -p standby.pub -s standby.key     # a different passphrase, a different place
```

Commit only the public halves, as `crates/rackhand-release/keys/current.pub` and `keys/standby.pub`. Until they are there, a
release build pins no key and `rackhand-verify` refuses everything (`no release keys are pinned in this build`).

Never put a private key, a passphrase or a signing script in the repository, in a workflow, or on a runner.

## A release

1. **Tag** the commit: `git tag -s v<X.Y.Z>` and push the tag. The `release` workflow builds every artifact on the maintainers'
   runners and uploads them as the workflow artifact `release-unsigned`: the binaries for each target, `install.sh`,
   `install.ps1`, `rackhand-windows-scripts.zip`, the unit files and an unsigned `manifest.json`. It also builds the hub and the
   probe twice, in two directories, and fails if the hashes differ.
2. **Rebuild the tag yourself**, on your machine, with the same command:

   ```sh
   git checkout v<X.Y.Z>
   cargo xtask release build --out dist-local --targets x86_64-unknown-linux-musl,x86_64-pc-windows-gnu
   ```

   The build runs in `/tmp/rackhand-release-target` whatever `CARGO_TARGET_DIR` says, on the runners and on your machine alike: OpenSSL,
   built by a build script, keeps the directory it was installed to inside the hub, so another directory is another binary.
   Don't pass `--target-dir`, and don't build in a path of your own choosing, when the aim is the same hashes.

3. **Check that every hash matches** what CI built. Download `release-unsigned`, then:

   ```sh
   (cd release-unsigned && sha256sum * | sort -k2) > ci.sums
   (cd dist-local       && sha256sum * | sort -k2) > local.sums
   diff ci.sums local.sums && echo identical
   ```

   Anything that differs is a reason to stop: do not sign it. A build that isn't reproducible, or a runner that was
   tampered with, looks like this.
4. **Sign** every file, then the manifest last (it lists the others' hashes). With `current.key`:

   ```sh
   cd dist-local
   VERSION=0.1.0     # the release's version, the tag without its v
   for f in $(ls | grep -v '\.minisig$' | grep -v '^manifest.json$'); do minisign -S -s ../current.key -m "$f" -t "file:$f version:$VERSION"; done
   minisign -S -s ../current.key -m manifest.json -t "file:manifest.json version:$VERSION"
   ```

   The trusted comment is `file:<name> version:<x.y.z>`, exactly. The helper and the updater take a binary's version
   from it, not from the request that brought the file, and refuse a version that isn't newer than the one installed;
   a signature with another file name or no version in its comment is refused, so an old signed release can't be
   replayed as a new one.

5. **Verify the directory** with the verifier built from the tag, which pins the real keys:

   ```sh
   cargo run -q -p rackhand-release --bin rackhand-verify -- --manifest dist-local
   ```

   It prints `ok current (<n> artifacts, version <X.Y.Z>)` only when the manifest is signed by a pinned key, every listed file has
   its listed hash, and no other file is there.
6. **Publish** `dist-local` as the GitHub release for the tag.

## If the current key is lost or exposed

Sign the next release with the **standby** key: installers, the helper and the updater accept it because they pin both keys
(E64). That release carries a new pair (a new current key, and a new standby key made the same way), so binaries installed
from it pin the new pair. A release signed by neither key is never installed.

## Trying the procedure (MV17)

The first time, run steps 4 and 5 with a throwaway pair instead of the real one: make two keys with `minisign -G`, put their
public halves in `crates/rackhand-release/keys/` in a scratch checkout, build `rackhand-verify` there, and sign and verify a
directory as above. Check that a file changed after signing, a file added to the directory, and a signature from a third key
are each refused. The tests in `crates/rackhand-release` do the same with the keys of `tests/keys/`; this is the one done by
hand with the real tool.
