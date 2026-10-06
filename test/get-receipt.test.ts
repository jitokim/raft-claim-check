// get_receipt on the in-memory store: visibility, the identical 404, and the key's current status.
import { describe, it, expect } from "vitest";
import { getReceipt, submitReceipt } from "../src/receipts";
import type { RevokedReason } from "../src/store";
import { agentKey, bindKey, DAY, encode, harness, HOUR, iso, MINUTE, receiptBody, runPayload, session, T0 } from "./helpers";

/** One stored receipt, submitted at T0 by agent_a on srv_a. */
async function setup() {
  const { store, call } = harness();
  const key = await agentKey();
  await bindKey(store, key);
  const submitted = await call(submitReceipt, await receiptBody(key, runPayload(key)));
  expect(submitted.status).toBe(201);
  const { duplicate: _duplicate, ...stored } = submitted.body;
  const read = (body: unknown, overrides: Parameters<typeof call>[2] = {}) => call(getReceipt, encode(body), { now: T0 + MINUTE, ...overrides });
  const revoke = (revokedAt: number, reason: RevokedReason, compromisedSince: string | null) =>
    store.revokeKey({ keyId: key.keyId, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(revokedAt), reason, compromisedSince });
  return { store, key, stored, id: stored.receipt_id as string, read, revoke };
}

describe("get_receipt", () => {
  it("returns {receipt_id, envelope, ledger} exactly as submit_receipt stored it, to any principal of the server", async () => {
    const { stored, id, read } = await setup();
    const own = await read({ receipt_id: id });
    expect(own.status).toBe(200);
    expect(own.body).toEqual(stored);
    expect(await read({ receipt_id: id }, { session: session({ principal_id: "agent_b" }) })).toEqual(own);
  });

  it("gives the identical 404 for unknown, malformed, expired and other-server IDs", async () => {
    const { id, read } = await setup();
    const notFound = { status: 404, body: { error: "receipt_not_found", hint: "No accessible, unexpired receipt has that ID." } };
    const cases = [
      read({ receipt_id: `rcpt_${"a".repeat(26)}` }),
      read({ receipt_id: "not-an-id" }),
      read({ receipt_id: "" }),
      read({ receipt_id: 42 }),
      read({ receipt_id: null }),
      read({}),
      read({ receipt_id: id }, { now: T0 + 90 * DAY }),
      read({ receipt_id: id }, { now: T0 + 120 * DAY }),
      read({ receipt_id: id }, { session: session({ server_id: "srv_b", server_slug: "b" }) }),
      read({ receipt_id: id }, { session: session({ server_id: "srv_b", server_slug: "b", principal_id: "agent_a" }) }),
    ];
    for (const result of await Promise.all(cases)) expect({ status: result.status, body: result.body }).toEqual(notFound);
    // One millisecond before expires_at it is still there.
    expect((await read({ receipt_id: id }, { now: T0 + 90 * DAY - 1 })).status).toBe(200);
  });

  it("shows a revocation that happened after submission; rotated and lost keys are not in a compromised window", async () => {
    const { stored, id, read, revoke } = await setup();
    await revoke(T0 + HOUR, "rotated", null);
    const result = await read({ receipt_id: id }, { now: T0 + 2 * HOUR });
    const ledger = stored.ledger as Record<string, unknown>;
    expect(result.body).toEqual({
      ...stored,
      ledger: { ...ledger, key: { ...(ledger.key as object), status: "revoked", revoked_at: iso(T0 + HOUR), compromised_window: false } },
    });
  });

  it("flags compromised_window when received_at >= compromised_since, inclusive", async () => {
    for (const [since, flagged] of [[T0 - DAY, true], [T0, true], [T0 + 1, false]] as const) {
      const { id, read, revoke } = await setup();
      await revoke(T0 + HOUR, "compromised", iso(since));
      const result = await read({ receipt_id: id }, { now: T0 + 2 * HOUR });
      expect(result.body.ledger).toMatchObject({ received_at: iso(T0), key: { status: "revoked", revoked_at: iso(T0 + HOUR), compromised_window: flagged } });
    }
  });

  it("400 for a body that is not a JSON object, without using a reservation", async () => {
    const { store, read } = await setup();
    const reservations = store.reservations.length;
    for (const body of ["", "[]", "not json", '{"receipt_id":"a","receipt_id":"b"}']) {
      const result = await read(body);
      expect(result.status).toBe(400);
      expect(result.body).toMatchObject({ error: "invalid_request" });
    }
    expect(store.reservations).toHaveLength(reservations);
  });

  it("uses the read reservation: 120 per minute, shared with get_session and list_keys", async () => {
    const { id, read } = await setup();
    for (let i = 0; i < 120; i++) expect((await read({ receipt_id: id }, { now: T0 + MINUTE + i })).status).toBe(200);
    const limited = await read({ receipt_id: id }, { now: T0 + MINUTE + 120 });
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({ error: "rate_limited", hint: "Read limit exceeded; retry after the indicated delay." });
    expect(Number(limited.headers.get("Retry-After"))).toBe(60);
  });
});
