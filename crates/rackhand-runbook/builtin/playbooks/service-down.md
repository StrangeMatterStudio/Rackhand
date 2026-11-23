+++
name = "service-down"
incident_kinds = ["service.not_active", "container.restarts"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "run_runbook", "add_incident_note", "finish_job", "exec"]
hosts = "incident"
max_runtime = "30m"
+++
## When
A service is not active, or a container keeps restarting.
## Read first
The incident, the machine's services and containers, and the recent journal of the unit (`journal`).
## Do
Read why it stopped before restarting it. Ask for `service-restart` or `compose-restart` with `run_runbook`; wait for the approval. If it fails again, look at disk space, memory and the recent change.
## Done when
The service is active and stays active for the time the incident waits, or you have said what is wrong.
## Stop and ask if
Restarting would lose data, the cause is a failing disk or memory, or the unit is not one the machine's role expects to run.
