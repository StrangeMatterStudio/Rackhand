//! The process list (FR-5): `Win32_Process` with each process's owner, as the helper collects it every 5 seconds, and which of
//! those run from somewhere an installed program doesn't: a user's `%TEMP%`, the system's Temp, or a user's Downloads.
//!
//! The helper's PowerShell line writes one object per process with the fields below (`StartMs` is Unix milliseconds):
//! `Get-CimInstance Win32_Process | ForEach-Object { ... } | ConvertTo-Json -Compress`.

use rackhand_proto::helper::ProcInfo;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Row {
    process_id: u32,
    #[serde(default)]
    parent_process_id: u32,
    #[serde(default)]
    executable_path: Option<String>,
    #[serde(default)]
    start_ms: i64,
    #[serde(default)]
    user_name: Option<String>,
}

/// Every process of the list. A process with no executable path (the System process, or one the helper may not look at) has
/// an empty `exe`.
pub fn parse(json: &str) -> Result<Vec<ProcInfo>, String> {
    // PowerShell writes one object, not a list of one
    let rows: Vec<Row> = match serde_json::from_str::<serde_json::Value>(json).map_err(|e| e.to_string())? {
        serde_json::Value::Array(items) => {
            items.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(|e| e.to_string())?
        }
        one @ serde_json::Value::Object(_) => vec![serde_json::from_value(one).map_err(|e| e.to_string())?],
        _ => return Err("the process list isn't a list".into()),
    };
    let exe_of: std::collections::BTreeMap<u32, String> =
        rows.iter().map(|r| (r.process_id, r.executable_path.clone().unwrap_or_default())).collect();
    Ok(rows
        .into_iter()
        .map(|r| ProcInfo {
            pid: r.process_id,
            ppid: r.parent_process_id,
            parent_exe: exe_of.get(&r.parent_process_id).cloned().unwrap_or_default(),
            exe: r.executable_path.unwrap_or_default(),
            user: r.user_name.unwrap_or_default(),
            started_at_ms: r.start_ms,
        })
        .collect())
}

/// Whether an executable's path is under a user's `%TEMP%` (`...\AppData\Local\Temp\`), the system's `...\Windows\Temp\`, or a
/// user's `Downloads` folder. Windows paths don't care about case, and a folder that only has the word in its name isn't it.
pub fn temp_or_downloads(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let user = p.contains(r"\users\");
    p.contains(r"\appdata\local\temp\")
        || p.get(1..).is_some_and(|rest| rest.starts_with(r":\windows\temp\"))
        || (user && p.contains(r"\downloads\"))
}

/// The processes of the list that run from there.
pub fn from_temp_or_downloads(all: &[ProcInfo]) -> Vec<ProcInfo> {
    all.iter().filter(|p| temp_or_downloads(&p.exe)).cloned().collect()
}
