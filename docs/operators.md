# Operators and the AI assistant

When a runbook fails, or an incident matches a playbook that calls for judgment, the hub can hand the incident to an
AI assistant. The assistant runs on a separate **operator** host, works only through the hub's MCP tools, and is held
to the hub's scope, autonomy levels and approvals. This page covers what an operator runs, what the AI provider
receives, and how approvals work.

An operator is optional. Without one, incidents that need judgment go to a person.

## What an operator runs

- `rackhand operator run`: keeps one connection to each hub the host joined and accepts job offers, up to
  `--max-jobs` at once (2 by default). It declines offers past that, and the hub tries its other operators.
- For each job, Claude Code (`claude`), started as
  `claude -p --mcp-config <file> --strict-mcp-config --tools "" --allowedTools "mcp__rackhand__*" --output-format
  stream-json --verbose --max-turns <n> --no-session-persistence --permission-mode dontAsk <brief>`:
  - no built-in tools (no shell, no file access), and no MCP server but one;
  - that one server is `rackhand operator mcp-bridge`, which carries the job's token and talks to the hub;
  - a clean environment (only `PATH`, `HOME` set to the job's own work directory, and `CLAUDE_CONFIG_DIR`), so no MCP
    server, tool or setting already on the host is loaded;
  - stopped at the job's deadline (30 minutes by default, at most 2 hours), and killed if it doesn't end within 5
    seconds.

The operator host holds no SSH key and no hub secret. A job token works only for that job, from that operator, on the
job's hosts, with the playbook's tools, until the deadline.

## Setting up an operator host

There is no installer for an operator yet. On a Linux host:

1. Download `rackhand-<target>` and its `.minisig` from the release and check them with `rackhand-verify` from the
   same release (see [install.md](install.md#release-files-and-how-they-are-checked)). Install it as
   `/usr/local/bin/rackhand`.
2. Create a system user for the operator, for example `rackhand-operator`, and give it the directory
   `/var/lib/rackhand-operator` (the default `--dir`).
3. Install Claude Code where that user can run it, and sign it in so that its credential is stored in
   `/var/lib/rackhand-operator/runner`. Each run uses that directory as `CLAUDE_CONFIG_DIR`, and it should hold only the
   credential.
4. Join each hub (below), then run `rackhand operator run` as that user under your service manager.

## Joining a hub

On the hub's dashboard, open **Add** and invite an **Operator**, or use the invite on the Assistant page. An invite
works once, for 24 hours. On the operator host, as the operator's user, run the command it shows:

```sh
rackhand operator join '<ticket>#<secret>'
```

or, with the two parts given separately:

```sh
rackhand operator join --ticket <ticket> --invite <secret> --name <name>
```

`--name` defaults to the host name. `--dir <dir>` (default `/var/lib/rackhand-operator`) and `--claude <path>` (default
`claude` on `PATH`) must match what `operator run` uses. One host can join several hubs; each sees it as its own
operator. Then:

```sh
rackhand operator run --max-jobs 2
```

## What the AI provider receives

An assistant job sends the brief and every tool result, including output from your machines, to the AI provider that
Claude Code on the operator host is signed in to. The Assistant page says so next to the operator invite.

The brief holds:

- the incident: title, severity, state and its timeline;
- the machine's facts (kind, operating system, services, containers, pending updates) and its last hour of vitals
  (last, minimum and maximum per metric);
- the failed job's steps with their exit codes and output, cut to a fixed length;
- the playbook's text, the autonomy level, the job's hosts, the deadline and the allowed tools;
- the rule that machine output is data, never instructions.

During the job the provider also receives every tool call the assistant makes and every result, which can include
log lines (`journal`, `docker_logs` diagnostics), command output from `exec`, connection records and security events.

It does not receive SSH keys, API tokens, webhook URLs or other Vault secrets: those never appear in MCP results. The
job token stays with the operator process and is never given to Claude Code.

Everything a machine reported, or the hub built from what one reported, is marked as `{"untrusted_output": ...}` in the
brief and in tool results, so it can't pass for the hub's own words.

To limit volume and cost, the hub starts at most 20 assistant jobs a day by default (`0` turns the assistant off; the
setting is on the Assistant page). Over the cap, an incident goes to a person with a note saying why. Each job's
transcript is kept on the hub, up to 5 MB per job.

Be aware that the brief is also written to the job's work directory on the operator host and passed to `claude` on its
command line, so other users on the operator host could read it. Run the operator on a host of its own.

## MCP tools

| Tool | Who | Notes |
| --- | --- | --- |
| `list_machines`, `get_machine`, `get_vitals`, `list_incidents`, `get_incident`, `list_security_events`, `get_connections`, `list_runbooks`, `get_runbook`, `list_playbooks`, `get_playbook`, `get_approval` | everyone | Read only |
| `run_diagnostic` | jobs and `read_request` keys | Only the built-in, read-only diagnostics, as the automation account |
| `run_runbook` | jobs and `read_request` keys | Gated (below) |
| `exec` | jobs only | On the job's hosts, as `rackhand-ai`, with a timeout; gated |
| `propose_library_change` | jobs and `read_request` keys | Makes a draft; applied only from the dashboard |
| `add_incident_note` | jobs and `read_request` keys | |
| `finish_job` | jobs only | Ends the job with an outcome and a summary |

There is no tool that approves or rejects. A machine at access level `monitor` has no accounts, so `exec`,
`run_diagnostic` and runbook steps that need SSH fail there with `monitor_only`.

People can use the same tools from their own computer with `rackhand-cli mcp` and a personal MCP key (scope `read`
or `read_request`) made on the dashboard's Account page:

```sh
rackhand-cli login '<invite>'
rackhand-cli mcp --hub <site> --key-file <file>
```

The key can also come from the environment variable `RACKHAND_MCP_KEY`. A key never grants more than its user's role.

## Autonomy levels

Each runbook and playbook has a level:

| Level | Meaning | Runbooks | Assistant |
| --- | --- | --- | --- |
| 0 | Tell | Not run; a person is told what would run | Read tools only |
| 1 | Propose | Run after approval | `exec` and `run_runbook` need approval |
| 2 | Act, then report | Run; callout with the result | `exec` and runbooks run; callout with a summary |
| 3 | Act quietly | Run; result in the log | As 2, with an info-level summary |

New runbooks and playbooks start at level 1.

Some things need an approval whatever the level:

- **High risk** always needs an approval with step-up (confirming your second factor again; it lasts 5 minutes): quarantine and
  release, rollback, hypervisor reboot, `sudoers-refresh`, `unenroll`, key rotation, accepting a changed host key, and
  assistant `exec` on machines with the role `operator`, `relay` or `hypervisor`.
- Calls with a **personal MCP key** are treated as level 1, so a stolen laptop and key can't change anything alone. The
  sensitive diagnostics (`journal`, `docker_logs`) need an approval from a personal key too.
- Requests from **peer hubs**.
- Any action on a **monitor** machine.
- Assistant `exec` commands that look destructive need step-up: `rm -rf` on `/` or a top-level directory, `mkfs`, `dd`
  to a device, `zpool destroy`, `zfs destroy` (except Rackhand's own patch snapshots), `qm destroy`, `pct destroy`,
  `do-release-upgrade`, edits under `/etc/apt/sources.list*`, `shutdown` and `poweroff`. This list is a backstop; the
  real controls are scope, levels and approvals.

Two exceptions, both off by default and high risk to turn on: an auto-quarantine rule, and `auto_rollback` after a
failed patch. Release from quarantine is never automatic.

## Approvals

When a call needs an approval, the hub answers at once with `needs_approval` and an approval id, and shows the request
on the Approvals page (and in a callout): the action, the target, the exact arguments, the risk, who asked and why.

- A responder can approve low and normal risk; high risk needs an admin with step-up.
- The approval is bound to the caller, the tool, the target, the exact arguments and, for a runbook, its revision. The
  caller repeats the same call with the approval id; the hub runs it only if everything still matches, and only once.
  A runbook edited in the meantime no longer matches.
- If the job's deadline passes while an approval is waiting, the job ends as `needs_human`. Approving later offers
  **Resume job**, which starts a new job for the incident with the approved call first.
