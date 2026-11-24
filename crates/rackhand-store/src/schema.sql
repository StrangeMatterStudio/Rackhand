-- Baseline schema (design 7.4.1). During initial development this single migration is edited in place; forward-only
-- migrations start with the first released version (design 13). Ids are ULID text, times Unix milliseconds (UTC),
-- JSON columns are TEXT.

CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE CHECK (name GLOB '[a-z0-9-]*' AND length(name) BETWEEN 1 AND 32),
  timezone TEXT NOT NULL,
  is_local INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE machines (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('linux', 'alpine', 'windows', 'appliance', 'hypervisor')),
  os TEXT,
  address TEXT,
  mode TEXT NOT NULL DEFAULT 'local' CHECK (mode IN ('local', 'remote')),
  access TEXT NOT NULL DEFAULT 'managed' CHECK (access IN ('managed', 'monitor')),
  probe_endpoint_id TEXT,
  driver TEXT,
  driver_settings TEXT, -- JSON: the driver's settings, each credential as `secret:driver.<id>` (7.3.12)
  roles TEXT NOT NULL DEFAULT '[]',
  tags TEXT NOT NULL DEFAULT '[]',
  policy_id TEXT REFERENCES policies(id),
  proxmox_ref TEXT,
  proxmox_ref_state TEXT NOT NULL DEFAULT 'none' CHECK (proxmox_ref_state IN ('none', 'proposed', 'confirmed', 'mismatch')),
  proxmox_ref_confirmed_by TEXT,
  enrolled_at INTEGER,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'enrolled', 'revoked')),
  quarantine TEXT NOT NULL DEFAULT 'none'
    CHECK (quarantine IN ('none', 'pending', 'applying', 'active', 'releasing', 'failed')),
  UNIQUE (site_id, name)
);
CREATE UNIQUE INDEX machines_probe_endpoint ON machines(probe_endpoint_id) WHERE probe_endpoint_id IS NOT NULL;

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  endpoint_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_seen_ms INTEGER,
  revoked_at INTEGER
);

CREATE TABLE operators (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  endpoint_id TEXT NOT NULL UNIQUE,
  runners TEXT NOT NULL DEFAULT '[]',
  max_jobs INTEGER NOT NULL DEFAULT 1,
  "order" INTEGER NOT NULL DEFAULT 0,
  last_seen_ms INTEGER,
  revoked_at INTEGER
);

CREATE TABLE peers (
  id TEXT PRIMARY KEY,
  site TEXT NOT NULL UNIQUE,
  endpoint_id TEXT NOT NULL UNIQUE,
  allowed_queries TEXT NOT NULL DEFAULT '["vitals","machine","incident"]',
  backup_quota_bytes INTEGER NOT NULL DEFAULT 0,
  added_at INTEGER NOT NULL,
  last_seen_ms INTEGER,
  revoked_at INTEGER,
  addrs TEXT NOT NULL DEFAULT '[]', -- JSON: the peer hub's direct addresses, from its ticket (7.3.4)
  relays TEXT NOT NULL DEFAULT '[]' -- JSON: the relays it can be reached through
);

CREATE TABLE peer_summaries (
  peer_id TEXT PRIMARY KEY REFERENCES peers(id),
  received_at_ms INTEGER NOT NULL,
  summary BLOB NOT NULL
);

CREATE TABLE join_tokens (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  hash BLOB NOT NULL UNIQUE,
  site_id TEXT REFERENCES sites(id),
  created_by TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  bound TEXT -- JSON: access level, machine id for level changes, role (7.3.1)
);

CREATE TABLE policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  patch TEXT NOT NULL DEFAULT 'approve-only' CHECK (patch IN ('auto', 'approve-only', 'hold')),
  security_window TEXT,
  full_window TEXT,
  window_length_min INTEGER NOT NULL DEFAULT 180,
  auto_reboot INTEGER NOT NULL DEFAULT 0,
  auto_rollback INTEGER NOT NULL DEFAULT 0,
  snapshot TEXT NOT NULL DEFAULT 'required' CHECK (snapshot IN ('required', 'optional')),
  quarantine TEXT NOT NULL DEFAULT 'approval' CHECK (quarantine IN ('approval', 'never')),
  expected_offline INTEGER NOT NULL DEFAULT 0,
  connections TEXT NOT NULL DEFAULT 'full' CHECK (connections IN ('full', 'summary', 'off')),
  transfer_roots TEXT NOT NULL DEFAULT '["/var/lib/rackhand-run/incoming"]',
  watch_internal INTEGER NOT NULL DEFAULT 0,
  peer_requests TEXT NOT NULL DEFAULT 'approval' CHECK (peer_requests IN ('approval', 'auto')),
  tunnel_ports TEXT NOT NULL DEFAULT '[22]',
  required_mounts TEXT NOT NULL DEFAULT '[]',
  thresholds TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE windows (
  id TEXT PRIMARY KEY,
  machine_id TEXT REFERENCES machines(id),
  tag TEXT,
  kind TEXT NOT NULL DEFAULT 'maintenance' CHECK (kind IN ('maintenance')),
  rrule TEXT NOT NULL,
  timezone TEXT NOT NULL,
  CHECK ((machine_id IS NULL) != (tag IS NULL))
);

CREATE TABLE metric_keys (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  unit TEXT NOT NULL DEFAULT '',
  label_set TEXT NOT NULL DEFAULT '{}',
  UNIQUE (name, label_set)
);

CREATE TABLE report_staging (
  machine_id TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL,
  offset_ms INTEGER NOT NULL DEFAULT 0,
  frame BLOB NOT NULL,
  PRIMARY KEY (machine_id, epoch, seq)
) WITHOUT ROWID;

CREATE TABLE probe_labels (
  machine_id TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  labels_id INTEGER NOT NULL,
  metric_key_id INTEGER NOT NULL DEFAULT 0,
  labels TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (machine_id, epoch, labels_id)
) WITHOUT ROWID;

CREATE TABLE series_chunks (
  machine_id TEXT NOT NULL,
  metric_key_id INTEGER NOT NULL,
  tier INTEGER NOT NULL CHECK (tier IN (0, 1, 2)),
  start_ms INTEGER NOT NULL,
  end_ms INTEGER NOT NULL,
  count INTEGER NOT NULL,
  closed INTEGER NOT NULL DEFAULT 0,
  data BLOB NOT NULL,
  PRIMARY KEY (machine_id, metric_key_id, tier, start_ms)
) WITHOUT ROWID;
CREATE INDEX series_chunks_tier_end ON series_chunks(tier, end_ms);

CREATE TABLE probe_ranges (
  machine_id TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  ranges TEXT NOT NULL,
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY (machine_id, epoch)
) WITHOUT ROWID;

CREATE TABLE rollup_dirty (
  machine_id TEXT NOT NULL,
  metric_key_id INTEGER NOT NULL,
  tier INTEGER NOT NULL CHECK (tier IN (1, 2)),
  from_ms INTEGER NOT NULL,
  to_ms INTEGER NOT NULL,
  PRIMARY KEY (machine_id, metric_key_id, tier, from_ms)
) WITHOUT ROWID;

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  machine_id TEXT,
  at_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  subject TEXT,
  data TEXT NOT NULL DEFAULT '{}',
  job_id TEXT
);
CREATE INDEX events_machine_at ON events(machine_id, at_ms);
CREATE INDEX events_at ON events(at_ms);

CREATE TABLE conn_records (
  machine_id TEXT NOT NULL,
  bucket_ms INTEGER NOT NULL,
  container TEXT NOT NULL DEFAULT '',
  exe TEXT NOT NULL,
  dest_ip TEXT NOT NULL,
  dest_port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  dest_asn INTEGER,
  dest_country TEXT,
  verdict TEXT,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (machine_id, bucket_ms, container, exe, dest_ip, dest_port, proto)
) WITHOUT ROWID;
CREATE INDEX conn_records_bucket ON conn_records(bucket_ms);

CREATE TABLE conn_baseline (
  machine_id TEXT NOT NULL,
  container TEXT NOT NULL DEFAULT '',
  exe TEXT NOT NULL,
  dest_asn INTEGER NOT NULL,
  dest_country TEXT NOT NULL,
  dest_port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (machine_id, container, exe, dest_asn, dest_country, dest_port, proto)
) WITHOUT ROWID;

CREATE TABLE baseline_buckets (
  machine_id TEXT NOT NULL,
  metric_key_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('hour_of_day', 'hour_of_week')),
  bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 167),
  mean REAL NOT NULL DEFAULT 0,
  var REAL NOT NULL DEFAULT 0,
  n INTEGER NOT NULL DEFAULT 0,
  frozen_until_ms INTEGER,
  PRIMARY KEY (machine_id, metric_key_id, kind, bucket)
) WITHOUT ROWID;

CREATE TABLE checks (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  interval_s INTEGER NOT NULL,
  machine_id TEXT REFERENCES machines(id),
  settings TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE check_results (
  check_id TEXT NOT NULL REFERENCES checks(id),
  at_ms INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  latency_ms REAL,
  detail TEXT,
  PRIMARY KEY (check_id, at_ms)
) WITHOUT ROWID;

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  machine_id TEXT,
  rule_id TEXT,
  dedupe_key TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  state TEXT NOT NULL CHECK (state IN ('open', 'automation', 'assistant', 'human', 'resolved')),
  title TEXT NOT NULL,
  opened_at INTEGER NOT NULL,
  acked_at INTEGER,
  acked_by TEXT,
  resolved_at INTEGER,
  resolved_by TEXT
);
CREATE UNIQUE INDEX incidents_open_dedupe ON incidents(dedupe_key) WHERE state != 'resolved';
CREATE INDEX incidents_opened ON incidents(opened_at);

CREATE TABLE incident_events (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  at_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX incident_events_incident ON incident_events(incident_id, at_ms);

CREATE TABLE silences (
  id TEXT PRIMARY KEY,
  machine_id TEXT,
  tag TEXT,
  rule_id TEXT,
  kind TEXT,
  until_ms INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('runbook', 'assistant')),
  name TEXT NOT NULL,
  rev INTEGER,
  target TEXT,
  params TEXT NOT NULL DEFAULT '{}',
  requested_by TEXT NOT NULL,
  incident_id TEXT,
  approval_id TEXT,
  state TEXT NOT NULL CHECK (state IN ('queued', 'waiting_approval', 'running', 'succeeded', 'failed', 'interrupted',
                                       'cancelled', 'timed_out')),
  started_at INTEGER,
  ended_at INTEGER,
  outcome TEXT,
  resumable_step TEXT
);
CREATE INDEX jobs_target_state ON jobs(target, state);

CREATE TABLE job_steps (
  job_id TEXT NOT NULL REFERENCES jobs(id),
  step_id TEXT NOT NULL,
  state TEXT NOT NULL,
  command TEXT,
  exit_code INTEGER,
  stdout BLOB CHECK (stdout IS NULL OR length(stdout) <= 1048576),
  stderr BLOB CHECK (stderr IS NULL OR length(stderr) <= 1048576),
  started_at INTEGER,
  ended_at INTEGER,
  PRIMARY KEY (job_id, step_id)
) WITHOUT ROWID;

CREATE TABLE assistant_transcripts (
  job_id TEXT NOT NULL REFERENCES jobs(id),
  seq INTEGER NOT NULL,
  at_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  text TEXT,
  PRIMARY KEY (job_id, seq)
) WITHOUT ROWID;

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  target TEXT,
  args TEXT NOT NULL DEFAULT '{}',
  runbook_rev INTEGER,
  args_hash BLOB NOT NULL,
  risk TEXT NOT NULL,
  step_up INTEGER NOT NULL DEFAULT 0,
  requested_by TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'used')),
  decided_by TEXT,
  decided_at INTEGER,
  expires_at INTEGER NOT NULL
);

CREATE TABLE quarantine_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  severity_at_least TEXT NOT NULL,
  event_kinds TEXT NOT NULL DEFAULT '[]',
  match TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 0,
  enabled_by TEXT,
  enabled_at INTEGER
);

CREATE TABLE library_items (
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('runbook', 'playbook', 'config')),
  origin TEXT NOT NULL CHECK (origin IN ('builtin', 'user')),
  rev INTEGER NOT NULL,
  PRIMARY KEY (kind, name)
) WITHOUT ROWID;

CREATE TABLE library_revisions (
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  rev INTEGER NOT NULL,
  content TEXT NOT NULL,
  author TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (kind, name, rev)
) WITHOUT ROWID;

CREATE TABLE library_drafts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,
  proposed_by TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL
);

CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  notifier TEXT NOT NULL,
  incident_id TEXT,
  at_ms INTEGER NOT NULL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE INDEX notifications_at ON notifications(at_ms);

CREATE TABLE secrets (
  name TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  rotated_at INTEGER
);

CREATE TABLE ssh_host_keys (
  machine_id TEXT NOT NULL REFERENCES machines(id),
  key_type TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  accepted_at INTEGER NOT NULL,
  accepted_by TEXT NOT NULL,
  PRIMARY KEY (machine_id, key_type)
) WITHOUT ROWID;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('viewer', 'responder', 'admin')),
  auth TEXT NOT NULL DEFAULT 'local' CHECK (auth IN ('local', 'oidc')),
  oidc_subject TEXT UNIQUE,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('password', 'totp', 'passkey')),
  data BLOB NOT NULL,
  last_totp_step INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE known_devices (
  user_id TEXT NOT NULL REFERENCES users(id),
  cookie_hash BLOB NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, cookie_hash)
) WITHOUT ROWID;

CREATE TABLE sessions (
  id_hash BLOB PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  step_up_at INTEGER,
  expires_at INTEGER NOT NULL
);

CREATE TABLE mcp_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  scope TEXT NOT NULL CHECK (scope IN ('read', 'read_request')),
  hash BLOB NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE job_tokens (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id),
  operator_id TEXT NOT NULL REFERENCES operators(id),
  hash BLOB NOT NULL UNIQUE,
  hosts TEXT NOT NULL DEFAULT '[]',
  tools TEXT NOT NULL DEFAULT '[]',
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE schedule_state (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  last_run_ms INTEGER,
  next_run_ms INTEGER,
  PRIMARY KEY (kind, key)
);

CREATE TABLE audit_log (
  seq INTEGER PRIMARY KEY,
  at_ms INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  data TEXT NOT NULL DEFAULT '{}',
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL,
  checkpoint INTEGER NOT NULL DEFAULT 0
);
