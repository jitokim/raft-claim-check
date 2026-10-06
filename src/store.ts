// The storage port the action handlers depend on, and its D1 implementation.

export type RateAction = "submit" | "register" | "revoke" | "read";

/** A sliding window: fewer than `max` reservations in the last `windowMs`, counted per principal or per server. */
export interface RateWindow { scope: "principal" | "server"; windowMs: number; max: number }

export interface Reservation { action: RateAction; serverId: string; principalId: string; nowMs: number }

/** Reservations inside one window: how many, and the oldest created_at (null when empty). */
export interface WindowUsage { count: number; oldest: number | null }

export type RevokedReason = "rotated" | "lost" | "compromised" | "operator";

export interface KeyRow {
  key_id: string;
  public_key: string;
  server_id: string;
  principal_id: string;
  principal_type: string;
  label: string | null;
  registered_at: string;
  revoked_at: string | null;
  revoked_reason: RevokedReason | null;
  compromised_since: string | null;
}

export type NewKey = Omit<KeyRow, "revoked_at" | "revoked_reason" | "compromised_since">;

export interface Revocation {
  keyId: string;
  serverId: string;
  principalId: string;
  revokedAt: string;
  reason: RevokedReason;
  compromisedSince: string | null;
}

/** A row of the v2 receipts table. Times are RFC 3339 UTC with milliseconds. */
export interface ReceiptRow {
  id: string;
  server_id: string;
  principal_id: string;
  principal_type: string;
  key_id: string;
  kind: "run" | "attest";
  signed_at: string;
  received_at: string;
  expires_at: string;
  envelope_json: string;
  ledger_json: string;
}

/** A stored receipt as read back, joined with its key's current revocation state. */
export interface StoredReceipt {
  id: string;
  envelope_json: string;
  ledger_json: string;
  received_at: string;
  key_revoked_at: string | null;
  key_compromised_since: string | null;
}

export interface Store {
  /** One atomic conditional insert into rate_reservations; true only if every window had room and the row was stored. */
  reserve(reservation: Reservation, windows: readonly RateWindow[]): Promise<boolean>;
  /** Usage of each window at reservation.nowMs, in the order given. Used only to compute Retry-After. */
  windowUsage(reservation: Reservation, windows: readonly RateWindow[]): Promise<WindowUsage[]>;
  getKey(keyId: string): Promise<KeyRow | null>;
  /**
   * One conditional insert of an active key. False when the principal already has `maxActive` active keys on the
   * server, or when a row with this key_id or public_key already exists.
   */
  insertKey(key: NewKey, maxActive: number): Promise<boolean>;
  /** The principal's keys on the server, revoked included, newest registered_at first. */
  listKeys(serverId: string, principalId: string): Promise<KeyRow[]>;
  /** Revokes the key only if it is bound to this server and principal and not yet revoked; true if it changed. */
  revokeKey(revocation: Revocation): Promise<boolean>;
  /** The key only if it is bound to exactly this server and principal, revoked or not. */
  getBoundKey(keyId: string, serverId: string, principalId: string): Promise<KeyRow | null>;
  /**
   * One conditional INSERT ... ON CONFLICT(id) DO NOTHING: the row is stored only while its bound key (key_id, server_id,
   * principal_id) is unrevoked. True only if this call stored the row.
   */
  insertReceipt(receipt: ReceiptRow): Promise<boolean>;
  /** One query: the receipt with this ID on this server, unexpired at `now` (RFC 3339), joined with its key's current state. */
  readReceipt(id: string, serverId: string, now: string): Promise<StoredReceipt | null>;
}

const KEY_COLUMNS = "key_id, public_key, server_id, principal_id, principal_type, label, registered_at, revoked_at, revoked_reason, compromised_since";

export class D1Store implements Store {
  constructor(private readonly db: D1Database) {}

  async reserve(reservation: Reservation, windows: readonly RateWindow[]): Promise<boolean> {
    const conditions: string[] = [];
    const binds: unknown[] = [reservation.serverId, reservation.principalId, reservation.action, reservation.nowMs];
    for (const window of windows) {
      const scoped = windowFilter(reservation, window);
      conditions.push(`(SELECT COUNT(*) FROM rate_reservations WHERE ${scoped.sql}) < ?`);
      binds.push(...scoped.binds, window.max);
    }
    const result = await this.db.prepare(
      `INSERT INTO rate_reservations (server_id, principal_id, action, units, created_at) SELECT ?, ?, ?, 1, ? WHERE ${conditions.join(" AND ") || "1"}`,
    ).bind(...binds).run();
    return result.meta.changes === 1;
  }

  async windowUsage(reservation: Reservation, windows: readonly RateWindow[]): Promise<WindowUsage[]> {
    return Promise.all(windows.map(async (window) => {
      const scoped = windowFilter(reservation, window);
      const row = await this.db.prepare(`SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM rate_reservations WHERE ${scoped.sql}`)
        .bind(...scoped.binds).first<WindowUsage>();
      return { count: row?.count ?? 0, oldest: row?.oldest ?? null };
    }));
  }

  async getKey(keyId: string): Promise<KeyRow | null> {
    return this.db.prepare(`SELECT ${KEY_COLUMNS} FROM keys WHERE key_id = ?`).bind(keyId).first<KeyRow>();
  }

  async insertKey(key: NewKey, maxActive: number): Promise<boolean> {
    const result = await this.db.prepare(
      "INSERT INTO keys (key_id, public_key, server_id, principal_id, principal_type, label, registered_at) SELECT ?, ?, ?, ?, ?, ?, ? " +
      "WHERE (SELECT COUNT(*) FROM keys WHERE server_id = ? AND principal_id = ? AND revoked_at IS NULL) < ? ON CONFLICT DO NOTHING",
    ).bind(key.key_id, key.public_key, key.server_id, key.principal_id, key.principal_type, key.label, key.registered_at, key.server_id, key.principal_id, maxActive).run();
    return result.meta.changes === 1;
  }

  async listKeys(serverId: string, principalId: string): Promise<KeyRow[]> {
    const result = await this.db.prepare(`SELECT ${KEY_COLUMNS} FROM keys WHERE server_id = ? AND principal_id = ? ORDER BY registered_at DESC, key_id DESC`)
      .bind(serverId, principalId).all<KeyRow>();
    return result.results;
  }

  async revokeKey(revocation: Revocation): Promise<boolean> {
    const result = await this.db.prepare(
      "UPDATE keys SET revoked_at = ?, revoked_reason = ?, compromised_since = ? WHERE key_id = ? AND server_id = ? AND principal_id = ? AND revoked_at IS NULL",
    ).bind(revocation.revokedAt, revocation.reason, revocation.compromisedSince, revocation.keyId, revocation.serverId, revocation.principalId).run();
    return result.meta.changes === 1;
  }

  async getBoundKey(keyId: string, serverId: string, principalId: string): Promise<KeyRow | null> {
    return this.db.prepare(`SELECT ${KEY_COLUMNS} FROM keys WHERE key_id = ? AND server_id = ? AND principal_id = ?`).bind(keyId, serverId, principalId).first<KeyRow>();
  }

  async insertReceipt(receipt: ReceiptRow): Promise<boolean> {
    const result = await this.db.prepare(
      "INSERT INTO receipts (id, server_id, principal_id, principal_type, key_id, kind, signed_at, received_at, expires_at, envelope_json, ledger_json) " +
      "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " +
      "WHERE EXISTS (SELECT 1 FROM keys WHERE key_id = ? AND server_id = ? AND principal_id = ? AND revoked_at IS NULL) ON CONFLICT(id) DO NOTHING",
    ).bind(receipt.id, receipt.server_id, receipt.principal_id, receipt.principal_type, receipt.key_id, receipt.kind, receipt.signed_at,
      receipt.received_at, receipt.expires_at, receipt.envelope_json, receipt.ledger_json, receipt.key_id, receipt.server_id, receipt.principal_id).run();
    return result.meta.changes === 1;
  }

  async readReceipt(id: string, serverId: string, now: string): Promise<StoredReceipt | null> {
    return this.db.prepare(
      "SELECT r.id, r.envelope_json, r.ledger_json, r.received_at, k.revoked_at AS key_revoked_at, k.compromised_since AS key_compromised_since " +
      "FROM receipts r JOIN keys k ON k.key_id = r.key_id WHERE r.id = ? AND r.server_id = ? AND r.expires_at > ?",
    ).bind(id, serverId, now).first<StoredReceipt>();
  }
}

function windowFilter(reservation: Reservation, window: RateWindow): { sql: string; binds: unknown[] } {
  const perPrincipal = window.scope === "principal";
  return {
    sql: `server_id = ?${perPrincipal ? " AND principal_id = ?" : ""} AND action = ? AND created_at > ?`,
    binds: [reservation.serverId, ...(perPrincipal ? [reservation.principalId] : []), reservation.action, reservation.nowMs - window.windowMs],
  };
}
