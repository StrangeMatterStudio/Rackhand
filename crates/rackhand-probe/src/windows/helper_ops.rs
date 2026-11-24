//! What the Windows helper answers (7.3.3): who owns a socket (by pid), the processes that run from `%TEMP%` or a Downloads
//! folder, and logon events since a cursor. The helper runs as SYSTEM, so it can see every process and the Security log, which
//! the probe's own service account can't. Answers come from PowerShell, parsed by [`super::parse`].

use rackhand_proto::helper::{AuthEvent, ProcInfo, SocketOwner};

use super::{parse, ps};

/// Every process with its owner, as `Win32_Process` and `Get-Process` give them.
const PROCESSES: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$users = @{}
Get-Process -IncludeUserName | ForEach-Object { $users[[int]$_.Id] = $_.UserName }
$list = @(Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{
    ProcessId = [int]$_.ProcessId
    ParentProcessId = [int]$_.ParentProcessId
    ExecutablePath = $_.ExecutablePath
    StartMs = if ($_.CreationDate) { ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } else { 0 }
    UserName = $users[[int]$_.ProcessId]
  }
})
ConvertTo-Json -InputObject $list -Compress"#;

/// Every process of the machine.
pub async fn processes() -> Result<Vec<ProcInfo>, String> {
    parse::procs::parse(&ps::run(PROCESSES).await?)
}

/// The processes that run from a user's `%TEMP%`, the system's Temp or a Downloads folder.
pub async fn process_scan() -> Result<Vec<ProcInfo>, String> {
    Ok(parse::procs::from_temp_or_downloads(&processes().await?))
}

/// Who owns each socket: the table rows carry a pid where Linux has an inode, so the ask is by pid.
pub async fn socket_owners(pids: &[u64]) -> Result<Vec<SocketOwner>, String> {
    let all = processes().await?;
    Ok(pids
        .iter()
        .filter_map(|pid| {
            let p = all.iter().find(|p| u64::from(p.pid) == *pid)?;
            Some(SocketOwner { inode: *pid, pid: p.pid, exe: p.exe.clone(), user: p.user.clone(), container: None })
        })
        .collect())
}

/// 4624 and 4625 from the Security log newer than `since_ms`.
fn logons_script(since_ms: i64) -> String {
    format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$since = [DateTimeOffset]::FromUnixTimeMilliseconds({since_ms}).UtcDateTime
$list = @(Get-WinEvent -FilterHashtable @{{ LogName = 'Security'; Id = 4624, 4625; StartTime = $since }} | ForEach-Object {{
  $data = @{{}}
  ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object {{ $data[$_.Name] = $_.'#text' }}
  [pscustomobject]@{{
    Id = [int]$_.Id
    TimeMs = ([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds()
    LogonType = [int]$data['LogonType']
    User = $data['TargetUserName']
    Domain = $data['TargetDomainName']
    Ip = $data['IpAddress']
  }}
}})
ConvertTo-Json -InputObject $list -Compress"#
    )
}

/// The logon events after `cursor` (a time in Unix milliseconds) and the cursor for the next ask. The first ask has no cursor and
/// starts from now: what happened before the probe was there is not its news.
pub async fn auth_since(cursor: Option<&str>, now_ms: i64) -> Result<(Vec<AuthEvent>, String), String> {
    let Some(since) = cursor.and_then(|c| c.parse::<i64>().ok()) else { return Ok((Vec::new(), now_ms.to_string())) };
    let events = parse::logon::parse(&ps::run(&logons_script(since)).await?)?;
    let events: Vec<AuthEvent> = events.into_iter().filter(|e| e.at_ms > since).collect();
    let next = events.iter().map(|e| e.at_ms).max().unwrap_or(since);
    Ok((events, next.to_string()))
}
