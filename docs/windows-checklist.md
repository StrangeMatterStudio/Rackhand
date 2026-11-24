# Windows checklist

There is no Windows CI runner yet (D81). What the unit tests can't cover on Windows (the services, the pipe, the scheduled
tasks) is checked by hand on a Windows 10 or 11 machine, in an elevated PowerShell, and each line is recorded as passed or
failed with the date. The parsers and the platform-neutral logic are covered by the unit tests; the Windows-only unit tests
are cross-built with `cargo test --no-run --lib -p <crate> --target x86_64-pc-windows-gnu` and the test binary is run on a
Windows host (`rackhand-release` `slots::windows_tests`, `rackhand-probe` `update::` and `windows::update::`).

The sections for installation, services, the pipe, collection and SSH come with T99. This section is probe self-update.

## Probe self-update (7.3.3, MV16)

Setup: a hub built with the test release keys (`lab-build`) and a newer version (`RACKHAND_LAB_VERSION=0.1.1`), the
Windows probe 0.1.0 (a `lab-build` too) installed with `install.ps1` and reporting, and in the hub's release directory a
manifest and `rackhand-probe-x86_64-pc-windows-gnu.exe` 0.1.1 with its `.minisig`, signed with the test keys and the comment
`file:rackhand-probe-x86_64-pc-windows-gnu.exe version:0.1.1`.

| # | Do | Expect |
| --- | --- | --- |
| 1 | Wait a minute after the probe connects | `C:\ProgramData\Rackhand\probe\update\probe` appears, the size of the release |
| 2 | `sc.exe qc RackhandProbe` and `sc.exe qc RackhandHelper` | Both run `C:\Program Files\Rackhand\probe-b.exe` (`service probe`, `service helper`) |
| 3 | `Get-Content C:\ProgramData\Rackhand\probe\probe.state` | `connected` and version `0.1.1`, within 2 minutes |
| 4 | `Get-Item 'C:\Program Files\Rackhand\probe-a.exe'` | The installer's `rackhand-probe.exe`, byte for byte (`Get-FileHash` equal) |
| 5 | `schtasks /Query /TN RackhandUpdateGuard /V /FO LIST` | Ran as `SYSTEM`; last result 0 |
| 6 | Publish 0.1.2 whose file is a signed program that exits at once (any small signed `.exe` that isn't a probe) | Within 3 minutes of the switch both services run `probe-b.exe` again and the state says `connected`, `0.1.1` |
| 7 | As the probe's account (`NT SERVICE\RackhandProbe`), try to write `C:\Program Files\Rackhand\probe-a.exe` | Access denied |
| 8 | Replace `C:\ProgramData\Rackhand\probe\update` by a junction to a folder with a signed release, then offer it again | The helper refuses it (`spool_unreadable` in the probe's report); no slot changes |
| 9 | Publish a release signed by another key | `update_refused` (`bad_signature`) on the hub; no slot changes |
