// One contract for the Store port, run against the in-memory fake and against D1Store on the real migrations.
import { describe, it, expect } from "vitest";
import { D1Store, type NewKey, type RateWindow, type ReceiptRow, type Reservation, type Store } from "../src/store";
import { MemoryStore } from "./memory-store";
import { migratedDatabase } from "./sqlite-d1";

const implementations: [string, () => Store][] = [
  ["MemoryStore", () => new MemoryStore()],
  ["D1Store on node:sqlite", () => new D1Store(migratedDatabase().d1)],
];

const T0 = Date.UTC(2026, 9, 6, 9, 0, 0);
const at = (nowMs: number, overrides: Partial<Reservation> = {}): Reservation => ({ action: "register", serverId: "srv_a", principalId: "agent_a", nowMs, ...overrides });

let counter = 0;
const newKey = (overrides: Partial<NewKey> = {}): NewKey => {
  counter += 1;
  const suffix = String(counter).padStart(4, "0");
  return {
    key_id: `ck_${"a".repeat(22)}${suffix}`, public_key: `ed25519:pk${suffix}`, server_id: "srv_a", principal_id: "agent_a",
    principal_type: "agent", label: null, registered_at: new Date(T0 + counter).toISOString(), ...overrides,
  };
};

describe.each(implementations)("%s", (_name, makeStore) => {
  describe("reserve", () => {
    const perPrincipal: RateWindow[] = [{ scope: "principal", windowMs: 60_000, max: 3 }];

    it("admits up to max in the window, then refuses without storing anything", async () => {
      const store = makeStore();
      for (let i = 0; i < 3; i++) expect(await store.reserve(at(T0 + i), perPrincipal)).toBe(true);
      expect(await store.reserve(at(T0 + 10), perPrincipal)).toBe(false);
      expect(await store.reserve(at(T0 + 11), perPrincipal)).toBe(false);
      expect(await store.windowUsage(at(T0 + 12), perPrincipal)).toEqual([{ count: 3, oldest: T0 }]);
    });

    it("slides: a reservation leaves the window exactly windowMs after it was made", async () => {
      const store = makeStore();
      for (let i = 0; i < 3; i++) expect(await store.reserve(at(T0), perPrincipal)).toBe(true);
      expect(await store.reserve(at(T0 + 59_999), perPrincipal)).toBe(false);
      expect(await store.reserve(at(T0 + 60_000), perPrincipal)).toBe(true);
    });

    it("counts other principals only in a server-scoped window, and never other actions or servers", async () => {
      const store = makeStore();
      const windows: RateWindow[] = [{ scope: "principal", windowMs: 60_000, max: 2 }, { scope: "server", windowMs: 60_000, max: 3 }];
      expect(await store.reserve(at(T0), windows)).toBe(true);
      expect(await store.reserve(at(T0, { principalId: "agent_b" }), windows)).toBe(true);
      expect(await store.reserve(at(T0, { principalId: "agent_c" }), windows)).toBe(true);
      // agent_a has one of its two, but the server has used three of three.
      expect(await store.reserve(at(T0 + 1), windows)).toBe(false);
      expect(await store.reserve(at(T0 + 1, { serverId: "srv_b" }), windows)).toBe(true);
      expect(await store.reserve(at(T0 + 1, { action: "revoke" }), windows)).toBe(true);
      expect(await store.windowUsage(at(T0 + 2), windows)).toEqual([{ count: 1, oldest: T0 }, { count: 3, oldest: T0 }]);
    });

    it("reports an empty window as count 0 and oldest null", async () => {
      expect(await makeStore().windowUsage(at(T0), [{ scope: "server", windowMs: 1000, max: 1 }])).toEqual([{ count: 0, oldest: null }]);
    });
  });

  describe("keys", () => {
    it("stores a new key as active and reads it back", async () => {
      const store = makeStore();
      const key = newKey({ label: "laptop" });
      expect(await store.insertKey(key, 5)).toBe(true);
      expect(await store.getKey(key.key_id)).toEqual({ ...key, revoked_at: null, revoked_reason: null, compromised_since: null });
      expect(await store.getKey("ck_unknown")).toBeNull();
    });

    it("refuses a second row with the same key_id or the same public_key", async () => {
      const store = makeStore();
      const key = newKey();
      expect(await store.insertKey(key, 5)).toBe(true);
      expect(await store.insertKey({ ...key, principal_id: "agent_b" }, 5)).toBe(false);
      expect(await store.insertKey(newKey({ public_key: key.public_key }), 5)).toBe(false);
      expect(await store.listKeys("srv_a", "agent_b")).toEqual([]);
    });

    it("caps active keys per principal per server; revoked keys and other pairs do not count", async () => {
      const store = makeStore();
      const first = newKey();
      expect(await store.insertKey(first, 2)).toBe(true);
      expect(await store.insertKey(newKey(), 2)).toBe(true);
      expect(await store.insertKey(newKey(), 2)).toBe(false);
      expect(await store.insertKey(newKey({ principal_id: "agent_b" }), 2)).toBe(true);
      expect(await store.insertKey(newKey({ server_id: "srv_b" }), 2)).toBe(true);
      expect(await store.revokeKey({ keyId: first.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: new Date(T0).toISOString(), reason: "lost", compromisedSince: null })).toBe(true);
      expect(await store.insertKey(newKey(), 2)).toBe(true);
    });

    it("lists one principal's keys on one server, newest first, revoked included", async () => {
      const store = makeStore();
      const older = newKey({ registered_at: "2026-10-06T09:00:00.000Z" });
      const newer = newKey({ registered_at: "2026-10-06T09:00:00.001Z" });
      const middle = newKey({ registered_at: "2026-10-06T09:00:00.000Z", key_id: `ck_${"z".repeat(26)}` });
      for (const key of [newer, older, middle, newKey({ principal_id: "agent_b" }), newKey({ server_id: "srv_b" })]) expect(await store.insertKey(key, 5)).toBe(true);
      await store.revokeKey({ keyId: older.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: "2026-10-06T10:00:00.000Z", reason: "rotated", compromisedSince: null });
      const listed = await store.listKeys("srv_a", "agent_a");
      // Equal registered_at falls back to key_id, descending.
      expect(listed.map((row) => row.key_id)).toEqual([newer.key_id, middle.key_id, older.key_id]);
      expect(listed[2]).toMatchObject({ revoked_at: "2026-10-06T10:00:00.000Z", revoked_reason: "rotated", compromised_since: null });
    });

    it("revokes only an active key bound to the given server and principal", async () => {
      const store = makeStore();
      const key = newKey();
      await store.insertKey(key, 5);
      const revocation = { keyId: key.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: "2026-10-06T10:00:00.000Z", reason: "compromised" as const, compromisedSince: key.registered_at };
      expect(await store.revokeKey({ ...revocation, principalId: "agent_b" })).toBe(false);
      expect(await store.revokeKey({ ...revocation, serverId: "srv_b" })).toBe(false);
      expect(await store.revokeKey(revocation)).toBe(true);
      expect(await store.revokeKey({ ...revocation, revokedAt: "2026-10-06T11:00:00.000Z", reason: "lost", compromisedSince: null })).toBe(false);
      expect(await store.getKey(key.key_id)).toMatchObject({ revoked_at: "2026-10-06T10:00:00.000Z", revoked_reason: "compromised", compromised_since: key.registered_at });
    });

    it("getBoundKey finds a key only under its own server and principal, revoked or not", async () => {
      const store = makeStore();
      const key = newKey();
      await store.insertKey(key, 5);
      expect(await store.getBoundKey(key.key_id, "srv_a", "agent_a")).toEqual({ ...key, revoked_at: null, revoked_reason: null, compromised_since: null });
      expect(await store.getBoundKey(key.key_id, "srv_b", "agent_a")).toBeNull();
      expect(await store.getBoundKey(key.key_id, "srv_a", "agent_b")).toBeNull();
      await store.revokeKey({ keyId: key.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: "2026-10-06T10:00:00.000Z", reason: "lost", compromisedSince: null });
      expect(await store.getBoundKey(key.key_id, "srv_a", "agent_a")).toMatchObject({ revoked_at: "2026-10-06T10:00:00.000Z" });
    });
  });

  describe("receipts", () => {
    const receiptRow = (key: NewKey, overrides: Partial<ReceiptRow> = {}): ReceiptRow => ({
      id: `rcpt_${"a".repeat(26)}`, server_id: "srv_a", principal_id: "agent_a", principal_type: "agent", key_id: key.key_id, kind: "run",
      signed_at: "2026-10-06T09:00:00.000Z", received_at: "2026-10-06T09:00:01.000Z", expires_at: "2027-01-04T09:00:01.000Z",
      envelope_json: '{"payload":{},"signature":{}}', ledger_json: '{"key":{}}', ...overrides,
    });

    it("inserts once per ID and reads back with the key's live state", async () => {
      const store = makeStore();
      const key = newKey();
      await store.insertKey(key, 5);
      const row = receiptRow(key);
      expect(await store.insertReceipt(row)).toBe(true);
      expect(await store.insertReceipt({ ...row, ledger_json: '{"other":true}' })).toBe(false);
      const stored = { id: row.id, envelope_json: row.envelope_json, ledger_json: row.ledger_json, received_at: row.received_at };
      expect(await store.readReceipt(row.id, "srv_a", "2026-10-06T10:00:00.000Z")).toEqual({ ...stored, key_revoked_at: null, key_compromised_since: null });
      await store.revokeKey({ keyId: key.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: "2026-10-07T00:00:00.000Z", reason: "compromised", compromisedSince: key.registered_at });
      expect(await store.readReceipt(row.id, "srv_a", "2026-10-07T10:00:00.000Z"))
        .toEqual({ ...stored, key_revoked_at: "2026-10-07T00:00:00.000Z", key_compromised_since: key.registered_at });
    });

    it("refuses to insert, and stores nothing, once the bound key is revoked", async () => {
      const store = makeStore();
      const key = newKey();
      await store.insertKey(key, 5);
      await store.revokeKey({ keyId: key.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: "2026-10-06T08:59:00.000Z", reason: "lost", compromisedSince: null });
      const row = receiptRow(key);
      expect(await store.insertReceipt(row)).toBe(false);
      expect(await store.readReceipt(row.id, "srv_a", "2026-10-06T10:00:00.000Z")).toBeNull();
    });

    it("reads only on the receipt's server and strictly before expires_at", async () => {
      const store = makeStore();
      const key = newKey();
      await store.insertKey(key, 5);
      const row = receiptRow(key);
      await store.insertReceipt(row);
      expect(await store.readReceipt(row.id, "srv_b", "2026-10-06T10:00:00.000Z")).toBeNull();
      expect(await store.readReceipt(`rcpt_${"b".repeat(26)}`, "srv_a", "2026-10-06T10:00:00.000Z")).toBeNull();
      expect(await store.readReceipt(row.id, "srv_a", "2027-01-04T09:00:00.999Z")).not.toBeNull();
      expect(await store.readReceipt(row.id, "srv_a", row.expires_at)).toBeNull();
    });
  });
});
