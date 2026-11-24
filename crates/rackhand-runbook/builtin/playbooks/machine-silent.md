+++
name = "machine-silent"
incident_kinds = ["machine.silent"]
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "run_runbook", "add_incident_note", "finish_job"]
hosts = "incident"
max_runtime = "30m"
+++
## When
A machine's probe has stopped reporting.
## Read first
The incident, when the machine last reported, its siblings' state, and the hypervisor's view if it is a guest.
## Do
Check whether the machine is up from another path (a check, its hypervisor's API, its neighbors). Do not reboot it unless a runbook for that exists and its approval is given.
## Done when
The machine reports again, or you have said whether it is down, cut off, or its probe stopped.
## Stop and ask if
The machine is the hub or a hypervisor, other machines at the site are silent too, or a power or network problem is likely.
