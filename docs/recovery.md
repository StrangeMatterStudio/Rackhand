# Backups and recovery

This page covers the hub's master key and recovery code, the hub's backups, and restoring a hub on a new machine.

## The master key and the recovery code

Every secret the hub keeps (its SSH keys, API tokens, webhook URLs, second-factor secrets) is encrypted in the
database with a 256-bit master key. The key is the file `/etc/rackhand/master.key` (root, 0600), outside the database.

The **recovery code** is the master key written out in Crockford base32 with a short checksum, in groups of five
characters. The installer prints it, and the last page of first run shows it once more. It is never shown again.

Without the master key, the secrets in the database and in every backup can't be read, and the hub won't start (it
stops with "the master key ... can't be read").

Keep, offline and apart from the hub:

1. the recovery code, written down or in a password manager;
2. a copy of `/etc/rackhand/master.key` itself. The restore command below takes the key as a file.

## Backups

The hub backs itself up every night at 02:00 in the site's time zone, into `/var/lib/rackhand/backups/`, and keeps the
newest 2. A backup is the database (taken with `VACUUM INTO`, so the hub keeps running), compressed, with the hub's
node key added, encrypted with the master key. Files are named `hub-<milliseconds>.rhbk`.

To take one now, as root on the hub:

```sh
rackhand hub backup
```

It prints the path of the new file. Copy backups off the hub regularly; a backup on the hub's own disk doesn't help if
the disk fails.

**Backups at a peer.** A peer hub can give this hub space for its backups (the peer's backup quota, 0 by default). The
hub then sends its latest backup to that peer each night, over direct paths only, and the peer keeps one copy. If this
hub is lost, an admin on the peer exports it, as root there:

```sh
rackhand hub peer-backup export <site> <file>
```

`<site>` is the lost hub's site name. Copy the file to the new machine.

## Restoring a hub on a new machine

A restored hub keeps its identity (its node key), so its probes, operators and peers reconnect without enrolling
again, as long as they can reach it at an address they know.

You need: a backup file, the master key file, and a fresh Debian 12 or later machine with no hub on it. Give it the old
hub's address if you can.

1. Download `rackhand-<target>` and its `.minisig` from the release, check them with `rackhand-verify` (see
   [install.md](install.md#release-files-and-how-they-are-checked)), and put the binary somewhere on `PATH`.
2. As root, restore:

   ```sh
   rackhand hub restore <file> --master-key <path>
   ```

   This writes the database, the node key and the master key, and a new `hub.toml` with default values. It refuses to
   run on a machine that already has a master key, node key or database. `--config-dir` (default `/etc/rackhand`) and
   `--data-dir` (default `/var/lib/rackhand`) choose other places.
3. Run the hub installer, `install.sh --hub` (see [install.md](install.md)). It finds the master key, keeps the keys and
   the database, sets the owners, installs the units and starts the hub. It prints "This machine had a hub already"
   instead of new codes.
4. Put back what you had changed in `hub.toml`: `relays`, `names` and `trusted_proxies` are back to their defaults
   after a restore. Restart the hub.
5. Sign in with your old accounts. Check the Overview: machines should report again within a minute or two.

## If the master key file is lost

If the hub's database is intact but `/etc/rackhand/master.key` is gone (a mistaken `rm`, a disk replaced), put the
offline copy of the key back as `/etc/rackhand/master.key`, owned by root with mode 0600, and start the hub
(`systemctl start rackhand-hub`).

If only the recovery code is left, the key can in principle be rebuilt from it: the code decodes to the 32 bytes of
the key. **There is no command that does this yet**, so keep the copy of the key file described above.

If both the key and the recovery code are lost, the secrets can't be recovered. A new hub has to be made with
`install.sh --hub`, and machines enrolled to it again (as root on each, `rackhand-probe uninstall`, then the new hub's
install command).

## Restoring the library

If you use the git mirror (Settings), runbooks and playbooks can be loaded back from a checkout of it, as root on the
hub:

```sh
rackhand hub restore-library <checkout>
```

Each file becomes a new revision; it prints how many were restored and which were refused.
