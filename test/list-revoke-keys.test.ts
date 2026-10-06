import { describe, it, expect } from "vitest";
import { listKeys, registerKey, revokeKey } from "../src/keys";
import { RATE_LIMITS } from "../src/ratelimit";
import type { NewKey } from "../src/store";
import { agentKey, encode, harness, HOUR, iso, MINUTE, registrationBody, session, statementFor, T0 } from "./helpers";
import type { MemoryStore } from "./memory-store";

const expectError = (result: { status: number; body: Record<string, unknown> }, status: number, code: string) => {
  expect(result.status).toBe(status);
  expect(result.body).toEqual({ error: code, hint: expect.any(String) });
};

async function seedKey(store: MemoryStore, registeredAt: number, overrides: Partial<NewKey> = {}): Promise<NewKey> {
  const key = await agentKey();
  const row: NewKey = {
    key_id: key.keyId, public_key: key.publicKey, server_id: "srv_a", principal_id: "agent_a", principal_type: "agent",
    label: `key-${registeredAt}`, registered_at: iso(registeredAt), ...overrides,
  };
  expect(await store.insertKey(row, 5)).toBe(true);
  return row;
}

describe("list_keys", () => {
  it("lists the caller's keys on the session's server, newest first, revoked included", async () => {
    const { store, call } = harness();
    const keys = [];
    for (let i = 0; i < 3; i++) {
      const key = await agentKey();
      const now = T0 + i * 1000;
      expect((await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(now), label: `machine-${i}` })), { now })).status).toBe(201);
      keys.push(key);
    }
    await seedKey(store, T0 + 5000, { principal_id: "agent_b" });
    await seedKey(store, T0 + 5000, { server_id: "srv_b" });
    expect((await call(revokeKey, encode({ key_id: keys[1].keyId, reason: "lost" }), { now: T0 + MINUTE })).status).toBe(200);

    const result = await call(listKeys, encode({}), { now: T0 + 2 * MINUTE });
    expect(result.status).toBe(200);
    const active = (i: number) => ({
      key_id: keys[i].keyId, public_key: keys[i].publicKey, label: `machine-${i}`, status: "active", registered_at: iso(T0 + i * 1000),
      revoked_at: null, revoked_reason: null, compromised_since: null,
    });
    expect(result.body).toEqual({
      keys: [active(2), { ...active(1), status: "revoked", revoked_at: iso(T0 + MINUTE), revoked_reason: "lost" }, active(0)],
    });
  });

  it("returns an empty list for a principal without keys", async () => {
    const { store, call } = harness();
    await seedKey(store, T0, { principal_id: "agent_b" });
    expect(await call(listKeys, encode({}))).toMatchObject({ status: 200, body: { keys: [] } });
  });

  it("needs a JSON object body without duplicate keys; other members are ignored", async () => {
    const { store, call } = harness();
    for (const body of ["", "[]", "null", '{"a":1,"a":2}']) expectError(await call(listKeys, encode(body)), 400, "invalid_request");
    expect(store.reservations).toHaveLength(0);
    expect((await call(listKeys, encode({ extra: true }))).status).toBe(200);
  });

  it("uses the shared read reservation: 120 per minute per agent", async () => {
    const { store, call } = harness();
    for (let i = 0; i < 120; i++) await store.reserve({ action: "read", serverId: "srv_a", principalId: "agent_a", nowMs: T0 - 20_000 }, RATE_LIMITS.read);
    const result = await call(listKeys, encode({}));
    expectError(result, 429, "rate_limited");
    expect(result.headers.get("Retry-After")).toBe("40");
    expect((await call(listKeys, encode({}), { now: T0 + 40_000 })).status).toBe(200);
  });
});

describe("revoke_key", () => {
  const REGISTERED = T0 - HOUR;

  it("revokes with reason rotated or lost; compromised_since stays null", async () => {
    const { store, call } = harness();
    for (const reason of ["rotated", "lost"]) {
      const key = await seedKey(store, REGISTERED);
      const result = await call(revokeKey, encode({ key_id: key.key_id, reason }));
      expect(result).toMatchObject({
        status: 200,
        body: {
          key_id: key.key_id, public_key: key.public_key, label: key.label, status: "revoked", registered_at: iso(REGISTERED),
          revoked_at: iso(T0), revoked_reason: reason, compromised_since: null,
        },
      });
      expect(Object.keys(result.body).sort()).toEqual(["compromised_since", "key_id", "label", "public_key", "registered_at", "revoked_at", "revoked_reason", "status"]);
      expect(await store.getKey(key.key_id)).toMatchObject({ revoked_at: iso(T0), revoked_reason: reason, compromised_since: null });
    }
  });

  it("compromised without compromised_since defaults it to registered_at", async () => {
    const { store, call } = harness();
    const key = await seedKey(store, REGISTERED);
    const result = await call(revokeKey, encode({ key_id: key.key_id, reason: "compromised" }));
    expect(result.body).toMatchObject({ status: "revoked", revoked_reason: "compromised", compromised_since: iso(REGISTERED) });
    expect(await store.getKey(key.key_id)).toMatchObject({ compromised_since: iso(REGISTERED) });
  });

  it("compromised with compromised_since stores it normalized to UTC milliseconds", async () => {
    const { store, call } = harness();
    const key = await seedKey(store, REGISTERED);
    // 10:30+02:00 is 08:30Z, between registered_at (08:00Z) and now (09:00Z).
    const result = await call(revokeKey, encode({ key_id: key.key_id, reason: "compromised", compromised_since: "2026-10-06T10:30:00+02:00" }));
    expect(result.body).toMatchObject({ revoked_reason: "compromised", compromised_since: "2026-10-06T08:30:00.000Z" });
  });

  it("accepts compromised_since equal to registered_at and equal to now", async () => {
    const { store, call } = harness();
    for (const since of [REGISTERED, T0]) {
      const key = await seedKey(store, REGISTERED);
      const result = await call(revokeKey, encode({ key_id: key.key_id, reason: "compromised", compromised_since: iso(since) }));
      expect(result.body).toMatchObject({ compromised_since: iso(since) });
    }
  });

  it("rejects compromised_since in the future, before registered_at, malformed, or without reason compromised", async () => {
    const { store, call } = harness();
    const key = await seedKey(store, REGISTERED);
    const bodies = [
      { key_id: key.key_id, reason: "compromised", compromised_since: iso(T0 + 1) },
      { key_id: key.key_id, reason: "compromised", compromised_since: iso(REGISTERED - 1) },
      { key_id: key.key_id, reason: "compromised", compromised_since: "yesterday" },
      { key_id: key.key_id, reason: "compromised", compromised_since: "2026-10-06T08:30:00" },
      { key_id: key.key_id, reason: "compromised", compromised_since: "2026-10-06" },
      { key_id: key.key_id, reason: "rotated", compromised_since: iso(REGISTERED) },
      { key_id: key.key_id, reason: "lost", compromised_since: iso(REGISTERED) },
    ];
    for (const body of bodies) expectError(await call(revokeKey, encode(body)), 400, "invalid_request");
    expect((await store.getKey(key.key_id))?.revoked_at).toBeNull();
  });

  it("rejects any other reason, and any other body, with invalid_request", async () => {
    const { store, call } = harness();
    const key = await seedKey(store, REGISTERED);
    for (const reason of ["operator", "ROTATED", "", "revoked"]) expectError(await call(revokeKey, encode({ key_id: key.key_id, reason })), 400, "invalid_request");
    const reservedBefore = store.reservations.length;
    const bodies: unknown[] = [
      "", "not json", "[]", "null", {}, { reason: "lost" }, { key_id: key.key_id }, { key_id: 1, reason: "lost" }, { key_id: key.key_id, reason: null },
      { key_id: key.key_id, reason: "compromised", compromised_since: null }, { key_id: key.key_id, reason: "compromised", compromised_since: 1_790_000_000_000 },
      { key_id: key.key_id, reason: "lost", note: "x" },
      `{"key_id":"${key.key_id}","reason":"lost","reason":"lost"}`,
    ];
    for (const body of bodies) expectError(await call(revokeKey, encode(body)), 400, "invalid_request");
    // Shape errors are answered before the reservation.
    expect(store.reservations).toHaveLength(reservedBefore);
    expect((await store.getKey(key.key_id))?.revoked_at).toBeNull();
  });

  it("validates the input before looking the key up", async () => {
    const { call } = harness();
    expectError(await call(revokeKey, encode({ key_id: "ck_unknown", reason: "stolen" })), 400, "invalid_request");
  });

  it("returns the identical 404 key_not_found for an unknown key and for another principal's or server's key", async () => {
    const { store, call } = harness();
    const otherPrincipal = await seedKey(store, REGISTERED, { principal_id: "agent_b" });
    const otherServer = await seedKey(store, REGISTERED, { server_id: "srv_b" });
    const results = [];
    for (const keyId of ["ck_aaaaaaaaaaaaaaaaaaaaaaaaaa", "", "not-a-key-id", otherPrincipal.key_id, otherServer.key_id]) {
      const result = await call(revokeKey, encode({ key_id: keyId, reason: "lost" }));
      expect(result.status).toBe(404);
      results.push(result.body);
    }
    expect(results[0]).toEqual({ error: "key_not_found", hint: expect.any(String) });
    for (const body of results) expect(body).toEqual(results[0]);
    expect((await store.getKey(otherPrincipal.key_id))?.revoked_at).toBeNull();
    expect((await store.getKey(otherServer.key_id))?.revoked_at).toBeNull();
  });

  it("returns 200 with the existing record for an already-revoked key and never changes compromised_since", async () => {
    const { store, call } = harness();
    const key = await seedKey(store, REGISTERED);
    const first = await call(revokeKey, encode({ key_id: key.key_id, reason: "compromised", compromised_since: iso(REGISTERED + MINUTE) }));
    expect(first.status).toBe(200);
    const again = [
      { key_id: key.key_id, reason: "compromised", compromised_since: iso(REGISTERED + 2 * MINUTE) },
      { key_id: key.key_id, reason: "compromised" },
      { key_id: key.key_id, reason: "rotated" },
      // Already revoked wins over the registered_at bound: there is nothing left to change.
      { key_id: key.key_id, reason: "compromised", compromised_since: iso(REGISTERED - HOUR) },
    ];
    for (const [index, body] of again.entries()) {
      expect(await call(revokeKey, encode(body), { now: T0 + (index + 1) * MINUTE })).toMatchObject({ status: 200, body: first.body });
    }
    expect(await store.getKey(key.key_id)).toMatchObject({ revoked_at: iso(T0), revoked_reason: "compromised", compromised_since: iso(REGISTERED + MINUTE) });
  });

  it("returns what a concurrent revocation stored when it lost the race", async () => {
    const { store } = harness();
    const key = await seedKey(store, REGISTERED);
    const racing = Object.assign(Object.create(store) as MemoryStore, {
      revokeKey: async () => {
        await store.revokeKey({ keyId: key.key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(T0 - 1), reason: "lost", compromisedSince: null });
        return false;
      },
    });
    const result = await harness({ store: racing }).call(revokeKey, encode({ key_id: key.key_id, reason: "compromised" }));
    expect(result).toMatchObject({ status: 200, body: { status: "revoked", revoked_at: iso(T0 - 1), revoked_reason: "lost", compromised_since: null } });
  });

  it("is limited to 10 per hour per agent, and a refused request changes nothing", async () => {
    const { store, call } = harness();
    const keys = [];
    for (let i = 0; i < 5; i++) keys.push(await seedKey(store, REGISTERED));
    for (let i = 0; i < 10; i++) expect((await call(revokeKey, encode({ key_id: keys[i % 4].key_id, reason: "lost" }), { now: T0 + i })).status).toBe(200);
    const result = await call(revokeKey, encode({ key_id: keys[4].key_id, reason: "lost" }), { now: T0 + 30 * MINUTE });
    expectError(result, 429, "rate_limited");
    expect(result.headers.get("Retry-After")).toBe(String(30 * 60));
    expect((await store.getKey(keys[4].key_id))?.revoked_at).toBeNull();
    // Another agent's budget is separate.
    expect((await call(revokeKey, encode({ key_id: keys[4].key_id, reason: "lost" }), { now: T0 + 30 * MINUTE, session: session({ principal_id: "agent_b" }) })).status).toBe(404);
  });
});
