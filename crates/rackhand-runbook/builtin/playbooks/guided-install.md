+++
name = "guided-install"
incident_kinds = []
autonomy = 1
risk = "normal"
tools = ["get_incident", "get_machine", "get_vitals", "run_diagnostic", "run_runbook", "add_incident_note", "finish_job", "exec", "propose_library_change"]
hosts = "site"
max_runtime = "30m"
+++
## When
A person asks for help installing or setting up something on a machine, from the dashboard.
## Read first
The request in the brief, the machine's facts, and which runbooks exist.
## Do
Plan the changes in order and say what each does. Make each change with `run_runbook` or `exec` and wait for its approval before the next; never batch them. Add a note after each.
## Done when
Every change in the plan has been approved and has run, and you have checked the result.
## Stop and ask if
A step is not reversible, a change would affect another machine, or the request is not what the brief says.
