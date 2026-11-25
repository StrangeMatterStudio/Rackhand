# Windows checklist

There is no Windows CI runner yet (D81). What the unit tests can't cover on Windows (the services, the pipe, the scheduled
tasks) is checked by hand on a Windows 10 or 11 machine, in an elevated PowerShell, and each line is recorded as passed or
failed with the date. The parsers and the platform-neutral logic are covered by the unit tests; the Windows-only unit tests
are cross-built with `cargo test --no-run --lib -p <crate> --target x86_64-pc-windows-gnu` and the test binary is run on a
Windows host (`rackhand-release` `slots::windows_tests`, `rackhand-probe` `update::` and `windows::update::`).

The sections are installation, the services, the helper's pipe, collection, SSH for managed machines, and probe
self-update. The commands use the installer's paths: `C:\Program Files\Rackhand` for the program and
`C:\ProgramData\Rackhand` for its data. Where the code doesn't yet do what the design says, the line says so. Record such
a line as failed until it is fixed.

## Installation (7.3.12, 7.3.3, MV16)

Setup: a hub (see [install.md](install.md)), and on the hub's Add page a Windows machine, managed, local. The page shows a
one-time command that works for 60 minutes. Install a second Windows machine the same way at `monitor`.

| # | Do | Expect |
| --- | --- | --- |
| 1 | Run the Add page's command (`iwr -useb <release>/install.ps1 -OutFile $env:TEMP\rackhand-install.ps1; & $env:TEMP\rackhand-install.ps1 -Ticket <ticket> -Token <token>`) | `Rackhand: enrolled as machine <id> (managed).` |
| 2 | Run the same command again | `rackhand install: the join failed`; the token works once |
| 3 | Run it in a PowerShell that isn't elevated, with a new token | `rackhand install: run it in an elevated PowerShell (as an administrator)`; nothing installed |
| 4 | `Get-ChildItem 'C:\Program Files\Rackhand'` | `rackhand-probe.exe`, `dispatch.ps1`, and the folders `scripts` and `schemas` |
| 5 | `Get-ChildItem C:\ProgramData\Rackhand\probe` | `probe.toml`, `probe.state` and the folder `data` |
| 6 | `icacls C:\ProgramData\Rackhand` | Only `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` and `BUILTIN\Administrators:(OI)(CI)(F)`; nothing inherited |
| 7 | `icacls C:\ProgramData\Rackhand\probe` | SYSTEM and Administrators with `(F)`, and `NT SERVICE\RackhandProbe:(OI)(CI)(M)` |
| 8 | `icacls C:\ProgramData\Rackhand\keys` | Only SYSTEM and Administrators |
| 9 | `icacls 'C:\Program Files\Rackhand'` | Users can read and run; only Administrators, SYSTEM and TrustedInstaller can write |
| 10 | `sc.exe qc RackhandProbe` | `START_TYPE: AUTO_START`; `BINARY_PATH_NAME` is `"C:\Program Files\Rackhand\rackhand-probe.exe" service probe`; `SERVICE_START_NAME: NT SERVICE\RackhandProbe` |
| 11 | `sc.exe qc RackhandHelper` | `AUTO_START`; `... rackhand-probe.exe" service helper`; `SERVICE_START_NAME: LocalSystem` |
| 12 | The hub's Overview | The machine is there within a minute; its Machine page shows access level managed and connection capture `sampling` |
| 13 | On the monitor machine: `Get-LocalUser rackhand`, `Get-Service sshd`, `Test-Path C:\ProgramData\Rackhand\keys` | No such user; no `sshd` service if it wasn't there before; `False` |

## Services (7.3.3, MV16)

Setup: the managed machine from the section above.

| # | Do | Expect |
| --- | --- | --- |
| 1 | `Get-Service RackhandHelper, RackhandProbe` | Both `Running`, start type `Automatic` |
| 2 | Restart the machine | Both are running again after the restart, and the probe reports to the hub without anything done by hand |
| 3 | `sc.exe qfailure RackhandProbe` and `sc.exe qfailure RackhandHelper` | `RESET_PERIOD (in seconds): 86400`; actions `RESTART -- Delay = 5000`, `30000`, `60000` milliseconds |
| 4 | `Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='RackhandProbe'").ProcessId -Force` | Within 10 seconds `Get-Service RackhandProbe` is `Running` again, with a new process id |
| 5 | The same for `RackhandHelper` | The same |
| 6 | `Stop-Service RackhandProbe`; wait; `Start-Service RackhandProbe` | Each takes a few seconds and ends `Stopped`, then `Running`; no error in the System log (`Get-WinEvent -LogName System -MaxEvents 20`); the Machine page shows a gap, then reports again |
| 7 | `Restart-Service RackhandHelper` while the probe runs | The probe keeps reporting; logon events (Collection, line 7) still arrive afterwards |
| 8 | `Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='RackhandProbe'").ProcessId -IncludeUserName` | `UserName` is `NT SERVICE\RackhandProbe` |
| 9 | `sc.exe qprivs RackhandProbe` and `sc.exe qsidtype RackhandProbe` | No required privileges are listed; SID type `UNRESTRICTED` |
| 10 | `Get-LocalGroupMember -SID S-1-5-32-544` | `NT SERVICE\RackhandProbe` isn't a member |

## The helper's pipe (7.3.3, MV16)

The helper (SYSTEM) answers the probe on `\\.\pipe\rackhand-helper`. Its security descriptor is
`D:P(A;;GA;;;SY)(A;;GRGW;;;<the SID of NT SERVICE\RackhandProbe>)`: SYSTEM and the probe's service account, nobody else,
and remote clients are refused.

| # | Do | Expect |
| --- | --- | --- |
| 1 | `Get-ChildItem \\.\pipe\ \| Where-Object Name -eq 'rackhand-helper'` | The pipe is there while `RackhandHelper` runs |
| 2 | As an administrator: `$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rackhand-helper', [System.IO.Pipes.PipeDirection]::InOut); $c.Connect(2000)` | `Access to the path is denied` (UnauthorizedAccessException): an administrator isn't the probe |
| 3 | The same from a PowerShell signed in as an ordinary local user | Refused the same way |
| 4 | From another Windows machine on the network, the same with `'<this machine's name>'` in place of `'.'` | Refused: remote clients are rejected |
| 5 | `Get-Content C:\ProgramData\Rackhand\probe\probe.state` | `connected`, with the installed version: the probe itself reaches the helper |

## Collection (FR-2, FR-4, FR-5, 7.3.3, MV16)

The probe reads vitals and services from CIM through one PowerShell call per interval, the TCP and UDP tables
(`GetExtendedTcpTable`, `GetExtendedUdpTable`, both address families) every 5 seconds, and asks the helper who owns each
socket, which processes run from a Temp or Downloads folder, and the Security log's logons (4624 and 4625, logon types 2,
3 and 10 only). Compare each line with the machine's page on the hub.

| # | Do | Expect |
| --- | --- | --- |
| 1 | `& 'C:\Program Files\Rackhand\rackhand-probe.exe' collect --once --json` | One JSON object listing the series `cpu.busy_pct`, `cpu.core_busy_pct` per core, `mem.used_pct`, `mem.available_bytes`, `uptime_s`, `disk.used_pct` per fixed drive (`C:` and others; no optical or removable drives), `net.rx_bps` and `net.tx_bps` per adapter, `diskio.read_bps` and `diskio.busy_pct` per physical disk |
| 2 | Compare with Task Manager and `Get-Volume` | CPU and memory within a few percent; each fixed drive's used space as `Get-Volume` shows it |
| 3 | The Machine page charts, after a few minutes | CPU, memory, disk and network series for this machine |
| 4 | `sc.exe create RackhandTestFail binPath= "C:\Windows\System32\cmd.exe /c exit 1" start= auto`, `Start-Service RackhandTestFail`, then `Get-CimInstance Win32_Service -Filter "Name='RackhandTestFail'" \| Select-Object State, StartMode, ExitCode` | `Stopped`, `Auto`, an exit code other than 0 and 1077; the Machine page lists `RackhandTestFail` as failed. Then `sc.exe delete RackhandTestFail` |
| 5 | `$t = [System.Net.Sockets.TcpClient]::new('example.com', 443)`, then after 30 seconds `$t.Close()` | Within a report or two the Machine page's connections show `powershell.exe` to that address on port 443, with its user (the tables are read every 5 seconds, so a connection shorter than that can be missed) |
| 6 | `$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 18080); $l.Start()`, then after a minute `$l.Stop()` | A `port.new_listener` event (warning) for port 18080 on the Security page |
| 7 | `auditpol /get /subcategory:Logon` | `Success and Failure`; if not, logon events can't be reported |
| 8 | `net use \\localhost\IPC$ /user:nosuchuser wrong` | An `auth.failed` event (network logon) for `nosuchuser` |
| 9 | Sign in to the machine with Remote Desktop | An `auth.login` event, method `remote_interactive`; sign-ins by services and scheduled tasks are not reported |
| 10 | `Copy-Item C:\Windows\System32\PING.EXE $env:TEMP\ping-test.exe; & $env:TEMP\ping-test.exe -n 30 localhost` | A `proc.exec_from_tmp` event at warning severity naming the file in Temp |
| 11 | The Machine page's pending updates | Not available yet: on Windows the helper doesn't run the Windows Update Agent search, so no pending updates are reported (the `updates_pending` diagnostic and `patch-windows` scan need SSH, below) |
| 12 | The Security page's file changes for this machine | Not available yet: the Windows helper doesn't hash the critical files of design 7.8.4, nor list containers |

## SSH for managed machines (7.3.7, MV16)

The design and the installer support managed Windows machines: OpenSSH Server, the accounts `rackhand` and
`rackhand-ai` (both local administrators with a random password nobody knows), the hub's keys in
`C:\ProgramData\Rackhand\keys\<account>`, and a block in `sshd_config` that `rackhand` can only reach `dispatch.ps1`
through.

| # | Do | Expect |
| --- | --- | --- |
| 1 | `Get-WindowsCapability -Online -Name OpenSSH.Server*` and `Get-Service sshd` | `Installed`; `sshd` `Running`, start type `Automatic` |
| 2 | `Get-LocalUser rackhand, rackhand-ai` and `Get-LocalGroupMember -SID S-1-5-32-544` | Both accounts exist and both are in Administrators |
| 3 | `Get-Content C:\ProgramData\Rackhand\keys\rackhand` and `...\rackhand-ai` | One key line each, starting with `from="` and the hub's addresses, and `no-agent-forwarding,no-X11-forwarding,no-port-forwarding` |
| 4 | `Get-Content C:\ProgramData\ssh\sshd_config` | `# BEGIN rackhand`, `Match User rackhand,rackhand-ai` with `AuthorizedKeysFile __PROGRAMDATA__/rackhand/keys/%u` and `PasswordAuthentication no`, `Match User rackhand` with a `ForceCommand` running `dispatch.ps1`, `# END rackhand`, all before `Match Group administrators` |
| 5 | `powershell -NoProfile -File 'C:\Program Files\Rackhand\dispatch.ps1' -Command 'diag-uptime {}'; $LASTEXITCODE` | The uptime, then `0` |
| 6 | The same with `-Command 'nosuch {}'`, then with `-Command 'diag-uptime {"x":"1"}'` | `no such script: nosuch` and `127`; `no such argument: x` and `2`; nothing run |
| 7 | `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | `EnableTranscripting` 1 and `OutputDirectory` `C:\ProgramData\Rackhand\transcripts`. This policy is machine-wide, so every PowerShell session on the machine is transcribed there, not only `rackhand-ai`'s |
| 8 | The Machine page, a few minutes after the join | Designed: the hub's SSH test passes as both accounts and the machine is enrolled. Not available yet: the test logs in as `rackhand` and runs `true`, which the dispatcher refuses (`no such script`), then as `rackhand-ai` runs `sudo -n true`, so on Windows it fails and the machine stays pending |
| 9 | Once line 8 passes: run the `uptime` diagnostic and a `patch-windows` scan on this machine from the hub | Each runs through the dispatcher and its output is on the Jobs page |
| 10 | Once line 8 passes: change the machine to `monitor` from its Machine page and run the command shown | The two accounts, `C:\ProgramData\Rackhand\keys` and the `# BEGIN rackhand` block are gone; `sshd` stays installed; the machine keeps its id and history. While the machine is pending, the Machine page refuses the change (only an enrolled machine changes its level) |

Not available yet on Windows: uninstalling (there is no `rackhand-probe uninstall` on Windows and the `unenroll` runbook
targets Linux and Alpine), and the hub's key rotation (the Windows helper refuses `ApplyKeys`).

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
