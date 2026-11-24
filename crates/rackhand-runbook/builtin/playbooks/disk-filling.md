+++
name = "disk-filling"
incident_kinds = ["disk.used", "disk.inodes", "disk.fill"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "run_runbook", "add_incident_note", "finish_job"]
hosts = "incident"
max_runtime = "30m"
+++
## When
A disk is nearly full, its inodes are, or its growth says it will be.
## Read first
The incident, the disk and inode series for the last week, and the machine's containers and services.
## Do
Find what grew with `disk` and `docker_logs` diagnostics. Propose what to clear or move; do not delete anything yourself. Ask for a runbook only if one exists for it.
## Done when
You have named the largest consumers and what a person should clear, or a runbook has run and the disk is below its threshold.
## Stop and ask if
Anything that would delete data is the next step, or the growth is a database or a volume you do not recognize.
