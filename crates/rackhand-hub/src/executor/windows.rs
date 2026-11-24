//! Steps for a Windows machine (7.3.7, D91): the automation key's `ForceCommand` runs the dispatcher, which accepts only
//! `<script-name> <json-args>`. This builds that one line from a step's `windows_script` and `windows_args`; the dispatcher
//! validates the arguments again against the script's schema, so what the hub sends is checked on both ends.

use std::collections::BTreeMap;

/// A script name as the dispatcher accepts it: lower-case words joined by dashes.
fn script_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// An argument name: letters and digits, starting with a letter.
fn arg_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric())
}

/// The command line for the dispatcher: the script, a space, and the arguments as one compact JSON object of strings.
pub fn command_line(script: &str, args: &BTreeMap<String, String>) -> Result<String, String> {
    if !script_name(script) {
        return Err(format!("`{script}` isn't a script name"));
    }
    if let Some(bad) = args.keys().find(|k| !arg_name(k)) {
        return Err(format!("`{bad}` isn't an argument name"));
    }
    if let Some((k, _)) = args.iter().find(|(_, v)| v.chars().any(char::is_control)) {
        return Err(format!("`{k}` holds a control character"));
    }
    let json = serde_json::to_string(args).map_err(|e| e.to_string())?;
    Ok(format!("{script} {json}"))
}

/// A job reference as the dispatcher takes it: the hub's own `<job id>/<step id>`, which are made of letters, digits and dashes.
fn job_ref(job: &str) -> Result<&str, String> {
    let fine = job.len() <= 128
        && job.split('/').count() == 2
        && job.split('/').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if fine { Ok(job) } else { Err(format!("`{job}` isn't a job reference")) }
}

/// `job-start`: the script runs as a scheduled task of its own, so a dropped connection doesn't stop it (7.3.7).
pub fn start_line(job: &str, script: &str, args: &BTreeMap<String, String>) -> Result<String, String> {
    let job = job_ref(job)?;
    // the same checks as for a plain step: the dispatcher won't start what it wouldn't run
    command_line(script, args)?;
    let body = serde_json::json!({ "job": job, "script": script, "args": args });
    Ok(format!("job-start {body}"))
}

/// `job-status`: the state, the exit code and the output from `offset`, as JSON.
pub fn status_line(job: &str, offset: u64) -> String {
    let job = job_ref(job).unwrap_or("-");
    format!("job-status {}", serde_json::json!({ "job": job, "offset": offset }))
}

/// `job-clean`: removes the task and its files once the result is recorded.
pub fn clean_line(job: &str) -> String {
    let job = job_ref(job).unwrap_or("-");
    format!("job-clean {}", serde_json::json!({ "job": job }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn the_line_is_the_script_and_its_arguments_as_compact_json_in_name_order() {
        assert_eq!(
            command_line("diag-journal", &args(&[("unit", "Spooler"), ("lines", "50"), ("since", "1 hours ago")]))
                .unwrap(),
            r#"diag-journal {"lines":"50","since":"1 hours ago","unit":"Spooler"}"#
        );
        assert_eq!(command_line("diag-df", &args(&[])).unwrap(), "diag-df {}");
    }

    #[test]
    fn quotes_and_backslashes_stay_inside_their_json_string() {
        let line = command_line("diag-du-top", &args(&[("path", r#"C:\Users\"x""#)])).unwrap();
        assert_eq!(line, r#"diag-du-top {"path":"C:\\Users\\\"x\""}"#);
        // read back, the value is what was given
        let json = line.split_once(' ').unwrap().1;
        let back: BTreeMap<String, String> = serde_json::from_str(json).unwrap();
        assert_eq!(back["path"], r#"C:\Users\"x""#);
    }

    #[test]
    fn what_the_dispatcher_would_not_take_is_not_sent() {
        for bad in ["", "Diag", "diag journal", "diag_journal", "-diag", "1diag", "diag;rm", &"a".repeat(65)] {
            assert!(command_line(bad, &args(&[])).is_err(), "{bad:?}");
        }
        assert!(command_line("diag-df", &args(&[("a b", "x")])).is_err());
        assert!(command_line("diag-df", &args(&[("x", "line\nbreak")])).is_err());
        assert!(command_line("diag-df", &args(&[("x", "tab\there")])).is_err());
    }
}

#[cfg(test)]
mod detached_tests {
    use super::*;

    #[test]
    fn a_detached_step_is_started_polled_and_cleaned_by_json_lines() {
        let args = BTreeMap::from([("phase".to_string(), "install".to_string())]);
        assert_eq!(
            start_line("01JJOB-1/install", "patch-windows", &args).unwrap(),
            r#"job-start {"args":{"phase":"install"},"job":"01JJOB-1/install","script":"patch-windows"}"#
        );
        assert_eq!(status_line("01JJOB-1/install", 120), r#"job-status {"job":"01JJOB-1/install","offset":120}"#);
        assert_eq!(clean_line("01JJOB-1/install"), r#"job-clean {"job":"01JJOB-1/install"}"#);
    }

    #[test]
    fn only_a_job_reference_the_hub_made_is_sent() {
        for bad in ["", "job", "a/b/c", "a/", "/b", "a b/c", "a;x/c", "../x/c", &format!("{}/s", "j".repeat(130))] {
            assert!(start_line(bad, "patch-windows", &BTreeMap::new()).is_err(), "{bad:?}");
        }
        // a script the dispatcher wouldn't run isn't started either
        assert!(start_line("j/s", "Patch", &BTreeMap::new()).is_err());
        // a bad reference in a poll can't name another job: it becomes one that doesn't exist
        assert_eq!(status_line("x y/z", 0), r#"job-status {"job":"-","offset":0}"#);
    }
}
