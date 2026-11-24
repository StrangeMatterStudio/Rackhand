+++
name = "backup-stale"
incident_kinds = ["backup.stale"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "run_runbook", "add_incident_note", "finish_job"]
hosts = "incident"
max_runtime = "30m"
+++
## When
The hub's backup or its git mirror is older than it should be.
## Read first
The incident, the hub's disk space, and the notifiers' state.
## Do
Read why the last run failed from the audit and the job logs. Ask for a runbook only if one exists; otherwise write what a person must fix.
## Done when
A new backup exists, or you have said exactly what blocks it.
## Stop and ask if
The backup location is full or unreachable and the fix is outside the hub.
