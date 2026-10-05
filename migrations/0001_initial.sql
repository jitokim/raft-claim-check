CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  principal_type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  confirmed INTEGER NOT NULL,
  contradicted INTEGER NOT NULL,
  cant_check INTEGER NOT NULL,
  body_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_server_created ON receipts(server_id, created_at);
CREATE INDEX IF NOT EXISTS receipts_expires ON receipts(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  server_slug TEXT NOT NULL,
  server_name TEXT,
  principal_id TEXT NOT NULL,
  principal_type TEXT NOT NULL,
  display_name TEXT,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS sessions_principal ON sessions(server_id, principal_id);
CREATE INDEX IF NOT EXISTS sessions_retention ON sessions(expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS rate_reservations (
  id INTEGER PRIMARY KEY,
  server_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  action TEXT NOT NULL,
  claim_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_principal ON rate_reservations(server_id, principal_id, action, created_at);
CREATE INDEX IF NOT EXISTS rate_server ON rate_reservations(server_id, action, created_at);

CREATE TABLE IF NOT EXISTS github_budget (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  remaining_reads INTEGER NOT NULL,
  reset_at INTEGER NOT NULL,
  reserved_inflight INTEGER NOT NULL
);
-- No assumed capacity: a real GitHub rate-limit response initializes the budget.
INSERT OR IGNORE INTO github_budget(id, remaining_reads, reset_at, reserved_inflight) VALUES (1, 0, 0, 0);

CREATE TABLE IF NOT EXISTS blocked_servers (
  server_id TEXT PRIMARY KEY,
  blocked_at TEXT NOT NULL,
  reason TEXT NOT NULL
);
