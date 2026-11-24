//! PowerShell, for what has no better API: one process per question, no profile, no window, killed if it takes too long. What
//! it prints is parsed by [`super::parse`], which is where the formats are tested.

use std::time::Duration;

use tokio::process::Command;

const LIMIT: Duration = Duration::from_secs(60);
/// `CREATE_NO_WINDOW`: a service has no desktop to show a console on.
const NO_WINDOW: u32 = 0x0800_0000;

/// Runs `script` and returns what it wrote to standard output.
pub async fn run(script: &str) -> Result<String, String> {
    let mut command = Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .creation_flags(NO_WINDOW)
        .kill_on_drop(true);
    let out = tokio::time::timeout(LIMIT, command.output())
        .await
        .map_err(|_| "powershell took too long".to_string())?
        .map_err(|e| format!("powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!("powershell exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').to_string())
}
