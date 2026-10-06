import { describe, it, expect } from "vitest";
import { registerKey } from "../src/keys";
import { RATE_LIMITS } from "../src/ratelimit";
import { agentKey, encode, harness, HOUR, iso, MINUTE, registrationBody, session, statementFor, T0 } from "./helpers";
import { MemoryStore } from "./memory-store";

// U+00E9 is two bytes in UTF-8, so 512 of them are exactly 1 KB.
const E_ACUTE = String.fromCharCode(0xe9);

const expectError =(result: { status: number; body: Record<string, unknown> }, status: number, code: string) => {
  expect(result.status).toBe(status);
  expect(result.body).toEqual({ error: code, hint: expect.any(String) });
};

describe("register_key", () => {
  it("201 for a new key, then 200 with the existing record on re-registration", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const created = await call(registerKey, await registrationBody(key, statementFor(key)));
    const record = {
      key_id: key.keyId, public_key: key.publicKey, label: "laptop", status: "active", registered_at: iso(T0),
      server: { id: "srv_a", slug: "a" }, principal: { id: "agent_a", type: "agent" },
    };
    expect(created).toMatchObject({ status: 201, body: record });
    expect(store.keys).toHaveLength(1);

    // A fresh statement with a new nonce and label, five minutes later: the stored record is returned unchanged.
    const again = statementFor(key, { label: "renamed", issued_at: iso(T0 + 5 * MINUTE) });
    expect(await call(registerKey, await registrationBody(key, again), { now: T0 + 5 * MINUTE })).toMatchObject({ status: 200, body: record });
    expect(store.keys).toHaveLength(1);
  });

  it("stores label null when the optional fields are absent", async () => {
    const { call } = harness();
    const key = await agentKey();
    const { label: _label, cli_version: _version, ...bare } = statementFor(key);
    const result = await call(registerKey, await registrationBody(key, bare));
    expect(result.status).toBe(201);
    expect(result.body.label).toBeNull();
  });

  it("registration_mismatch for another server_id, and separately for another principal_id", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { server_id: "srv_b" }))), 400, "registration_mismatch");
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { principal_id: "agent_b" }))), 400, "registration_mismatch");
    expect(store.keys).toHaveLength(0);
  });

  it("registration_expired 11 minutes in the past and 11 minutes in the future; exactly 10 minutes is accepted", async () => {
    const { call } = harness();
    const key = await agentKey();
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(T0 - 11 * MINUTE) }))), 400, "registration_expired");
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(T0 + 11 * MINUTE) }))), 400, "registration_expired");
    expect((await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(T0 - 10 * MINUTE) })))).status).toBe(201);
    expect((await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(T0 + 10 * MINUTE) })))).status).toBe(200);
  });

  it("bad_signature when key_id does not match public_key", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const other = await agentKey();
    // Well-formed and correctly signed by `key`, but naming the other key's ID in both places.
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { key_id: other.keyId }))), 400, "bad_signature");
    expect(store.keys).toHaveLength(0);
  });

  it("bad_signature for a tampered statement and for every other signature fault", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const other = await agentKey();
    const payload = statementFor(key);
    const value = await key.sign(payload);
    const signed = (changes: { payload?: Record<string, unknown>; signature?: Record<string, unknown> }) =>
      encode({ registration: { payload: { ...payload, ...changes.payload }, signature: { alg: "ed25519", key_id: key.keyId, value, ...changes.signature } } });

    expect((await call(registerKey, signed({}))).status).toBe(201);
    store.keys.length = 0;

    const faults = [
      signed({ payload: { label: "tampered" } }),
      signed({ payload: { nonce: "tampered" } }),
      signed({ signature: { value: await other.sign(payload) } }),
      signed({ signature: { alg: "Ed25519" } }),
      signed({ signature: { key_id: other.keyId } }),
      signed({ signature: { value: value.slice("ed25519:".length) } }),
      signed({ signature: { value: `${value}=` } }),
      // Another key's public key with this key's signature: the statement's own public_key is what verifies.
      signed({ payload: { public_key: other.publicKey, key_id: other.keyId }, signature: { key_id: other.keyId } }),
    ];
    // An hour apart, so the register budget of 5 per hour never decides the outcome.
    for (const [index, body] of faults.entries()) expectError(await call(registerKey, body, { now: T0 + (index + 1) * HOUR }), 400, "bad_signature");
    expect(store.keys).toHaveLength(0);
  });

  it("key_revoked for a revoked key, whoever registers it", async () => {
    const { store, call } = harness({ now: T0 });
    const key = await agentKey();
    expect((await call(registerKey, await registrationBody(key, statementFor(key)))).status).toBe(201);
    await store.revokeKey({ keyId: key.keyId, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(T0 + MINUTE), reason: "rotated", compromisedSince: null });
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { issued_at: iso(T0 + 2 * MINUTE) })), { now: T0 + 2 * MINUTE }), 409, "key_revoked");
    const elsewhere = statementFor(key, { principal_id: "agent_b", issued_at: iso(T0 + 2 * MINUTE) });
    expectError(await call(registerKey, await registrationBody(key, elsewhere), { now: T0 + 2 * MINUTE, session: session({ principal_id: "agent_b" }) }), 409, "key_revoked");
  });

  it("key_bound_elsewhere for another principal or another server", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    expect((await call(registerKey, await registrationBody(key, statementFor(key)))).status).toBe(201);
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { principal_id: "agent_b" })), { session: session({ principal_id: "agent_b" }) }), 409, "key_bound_elsewhere");
    expectError(await call(registerKey, await registrationBody(key, statementFor(key, { server_id: "srv_b" })), { session: session({ server_id: "srv_b", server_slug: "b" }) }), 409, "key_bound_elsewhere");
    expect(store.keys).toHaveLength(1);
  });

  it("too_many_keys on the sixth active key; revoking one frees a slot", async () => {
    const { store, call } = harness();
    for (let i = 0; i < 5; i++) {
      const key = await agentKey();
      expect((await call(registerKey, await registrationBody(key, statementFor(key)))).status).toBe(201);
    }
    // Five registrations use the hourly register budget too, so the sixth comes an hour later.
    const later = T0 + HOUR;
    const sixth = await agentKey();
    const body = await registrationBody(sixth, statementFor(sixth, { issued_at: iso(later) }));
    expectError(await call(registerKey, body, { now: later }), 409, "too_many_keys");
    expect(store.keys).toHaveLength(5);

    await store.revokeKey({ keyId: store.keys[0].key_id, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(later), reason: "lost", compromisedSince: null });
    expect((await call(registerKey, body, { now: later + 1 })).status).toBe(201);
  });

  it("returns the stored record when a concurrent request inserted the same key first", async () => {
    const key = await agentKey();
    const store = new MemoryStore();
    const { call: first } = harness({ store });
    expect((await first(registerKey, await registrationBody(key, statementFor(key)))).status).toBe(201);
    // The pre-insert lookup misses (as if the other request had not committed yet); the insert then conflicts.
    let lookups = 0;
    const racing = Object.assign(Object.create(store) as MemoryStore, { getKey: async (id: string) => (lookups++ === 0 ? null : store.getKey(id)) });
    const { call } = harness({ store: racing });
    const result = await call(registerKey, await registrationBody(key, statementFor(key)));
    expect(result.status).toBe(200);
    expect(result.body.key_id).toBe(key.keyId);
  });

  it("429 before any signature work: a rate-limited request with a bad signature", async () => {
    const { store, call } = harness();
    for (let i = 0; i < 5; i++) await store.reserve({ action: "register", serverId: "srv_a", principalId: "agent_a", nowMs: T0 - 30 * MINUTE }, RATE_LIMITS.register);
    const key = await agentKey();
    const other = await agentKey();
    const result = await call(registerKey, await registrationBody(key, statementFor(key), {}, other));
    expectError(result, 429, "rate_limited");
    expect(result.headers.get("Retry-After")).toBe(String(30 * 60));
    expect(store.reservations).toHaveLength(5);
    expect(store.keys).toHaveLength(0);
  });

  it("invalid_request for a body with duplicate keys, at any depth", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const good = new TextDecoder().decode(await registrationBody(key, statementFor(key)));
    expectError(await call(registerKey, encode(good.replace('{"registration":', '{"registration":{},"registration":'))), 400, "invalid_request");
    expectError(await call(registerKey, encode(good.replace('"label":"laptop"', '"label":"laptop","label":"laptop"'))), 400, "invalid_request");
    expect(store.keys).toHaveLength(0);
  });

  it("invalid_request for a malformed body, before the reservation", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const payload = statementFor(key);
    const signature = { alg: "ed25519", key_id: key.keyId, value: await key.sign(payload) };
    const bodies: unknown[] = [
      "", "not json", "[]", "null", "{}", '{"registration":{"payload":{},"signature":{}},"x":1.5}',
      { registration: null },
      { registration: { payload } },
      { registration: { payload, signature, extra: true } },
      { registration: { payload: [], signature } },
      { registration: { payload, signature: "ed25519:x" } },
      { registration: { payload, signature: { ...signature, value: 1 } } },
      { registration: { payload, signature: { alg: "ed25519", key_id: key.keyId } } },
      { registration: { payload, signature: { ...signature, extra: "x" } } },
      { registration: { payload, signature }, extra: 1 },
    ];
    for (const body of bodies) expectError(await call(registerKey, encode(body)), 400, "invalid_request");
    expect(store.reservations).toHaveLength(0);
  });

  it("invalid_request for a malformed statement, after the reservation", async () => {
    const { store, call } = harness();
    const key = await agentKey();
    const { nonce: _nonce, ...withoutNonce } = statementFor(key);
    const statements = [
      statementFor(key, { schema: "claim-check.receipt.v2" }),
      statementFor(key, { schema: "claim-check.key-registration.v3" }),
      withoutNonce,
      statementFor(key, { nonce: "" }),
      statementFor(key, { server_id: 7 }),
      statementFor(key, { label: null }),
      statementFor(key, { cli_version: true }),
      statementFor(key, { label: "x".repeat(1025) }),
      statementFor(key, { label: E_ACUTE.repeat(513) }),
      statementFor(key, { extra: "field" }),
      statementFor(key, { public_key: "ed25519:short" }),
      statementFor(key, { public_key: key.publicKey.replace("ed25519:", "ED25519:") }),
      statementFor(key, { key_id: key.keyId.toUpperCase() }),
      statementFor(key, { key_id: `${key.keyId}a` }),
      statementFor(key, { issued_at: "2026-10-06T09:00:00Z" }),
      statementFor(key, { issued_at: "2026-10-06T09:00:00.000+00:00" }),
      statementFor(key, { issued_at: "2026-02-30T09:00:00.000Z" }),
    ];
    for (const [index, statement] of statements.entries()) {
      const result = await call(registerKey, await registrationBody(key, statement), { now: T0 + index * HOUR });
      expect(result.body, JSON.stringify(statement).slice(0, 200)).toEqual({ error: "invalid_request", hint: expect.any(String) });
    }
    expect(store.keys).toHaveLength(0);
    expect(store.reservations).toHaveLength(statements.length);
  });

  it("accepts a 1 KB label and cli_version", async () => {
    const { call } = harness();
    const key = await agentKey();
    const result = await call(registerKey, await registrationBody(key, statementFor(key, { label: "x".repeat(1024), cli_version: E_ACUTE.repeat(512) })));
    expect(result.status).toBe(201);
    expect(result.body.label).toBe("x".repeat(1024));
  });
});
