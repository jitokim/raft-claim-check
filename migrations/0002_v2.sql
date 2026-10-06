DROP TABLE IF EXISTS github_budget;

-- v1 receipts are GitHub verdicts in a different shape; they are not migrated.
DROP TABLE IF EXISTS receipts;

CREATE TABLE keys (
  key_id            TEXT PRIMARY KEY,           -- "ck_" + 26 chars base32
  public_key        TEXT NOT NULL UNIQUE,       -- "ed25519:" + base64url; one binding per key, ever
  server_id         TEXT NOT NULL,
  principal_id      TEXT NOT NULL,
  principal_type    TEXT NOT NULL,
  label             TEXT,
  registered_at     TEXT NOT NULL,              -- RFC 3339 UTC, app clock
  revoked_at        TEXT,
  revoked_reason    TEXT CHECK (revoked_reason IN ('rotated','lost','compromised','operator')),
  compromised_since TEXT
);
CREATE INDEX keys_principal ON keys (server_id, principal_id);

CREATE TABLE receipts (
  id             TEXT PRIMARY KEY,              -- "rcpt_" + 26 chars base32 of SHA-256(JCS(payload))
  server_id      TEXT NOT NULL,
  principal_id   TEXT NOT NULL,
  principal_type TEXT NOT NULL,
  key_id         TEXT NOT NULL REFERENCES keys(key_id),
  kind           TEXT NOT NULL CHECK (kind IN ('run','attest')),
  signed_at      TEXT NOT NULL,                 -- asserted, copied from payload
  received_at    TEXT NOT NULL,                 -- app clock
  expires_at     TEXT NOT NULL,                 -- received_at + 90 days
  envelope_json  TEXT NOT NULL,                 -- the envelope exactly as parsed, re-serialized as JCS
  ledger_json    TEXT NOT NULL                  -- the ledger at insert; key status is joined live on read
);
CREATE INDEX receipts_server_received ON receipts (server_id, received_at);
CREATE INDEX receipts_key_received ON receipts (key_id, received_at);
CREATE INDEX receipts_expires ON receipts (expires_at);

ALTER TABLE rate_reservations RENAME COLUMN claim_count TO units;
-- action is now one of: 'submit', 'register', 'revoke', 'read'
