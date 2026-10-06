// The Worker's fetch handler end to end, on node:sqlite with the real migrations.
import { createHmac } from "node:crypto";
import { describe, it, expect } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";
import { receiptId } from "../src/crypto";
import { canonicalize } from "../src/jcs";
import { agentKey, receiptBody, registrationBody, runPayload, statementFor } from "./helpers";
import { migratedDatabase } from "./sqlite-d1";

const ORIGIN = "https://claim-check.ohmygraph.workers.dev";
const SECRET = "test-session-secret";
const RAW_ID = "ab".repeat(32);

function setup() {
  const { d1, sqlite } = migratedDatabase();
  const env: Env = { DB: d1, CANONICAL_ORIGIN: ORIGIN, RAFT_CLIENT_ID: "client", RAFT_CLIENT_SECRET: "secret", SESSION_SECRET: SECRET };
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  sqlite.prepare("INSERT INTO sessions (id_hash, server_id, server_slug, server_name, principal_id, principal_type, display_name, scopes, created_at, expires_at, revoked_at) VALUES (?, 'srv_a', 'a', 'Server A', 'agent_a', 'agent', 'Agent A', 'openid profile', ?, ?, NULL)")
    .run(createHmac("sha256", SECRET).update(RAW_ID).digest("hex"), new Date().toISOString(), expiresAt);
  const call = (path: string, body: BodyInit | null, cookie: string | null = `cc_session=${RAW_ID}`) =>
    worker.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", body, headers: cookie ? { Cookie: cookie } : {} }), env);
  return { env, sqlite, call, expiresAt };
}

describe("router", () => {
  it("checks size before the session", async () => {
    const { call } = setup();
    const response = await call("/api/agent/actions/get-session", new Uint8Array(65_537), null);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request", hint: "Request body exceeds 64 KB." });
  });

  it("accepts a 64 KB body", async () => {
    const { call } = setup();
    expect((await call("/api/agent/actions/get-session", `${" ".repeat(65_534)}{}`)).status).toBe(200);
  });

  it("returns v1's 401 without a valid session and 403 for a blocked server", async () => {
    const { call, sqlite } = setup();
    for (const cookie of [null, "cc_session=nothex", `cc_session=${"cd".repeat(32)}`]) {
      const response = await call("/api/agent/actions/get-session", "{}", cookie);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "not_authenticated", hint: "Run raft integration login to create a Claim Check session." });
    }
    sqlite.prepare("INSERT INTO blocked_servers (server_id, blocked_at, reason) VALUES ('srv_a', '2026-10-06T00:00:00.000Z', 'test')").run();
    const response = await call("/api/agent/actions/get-session", "{}");
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "not_authorized", hint: "This Raft server is not authorized to use Claim Check." });
  });

  it("get_session is unchanged: body, lenient JSON object, 120 reads per minute", async () => {
    const { call, sqlite, expiresAt } = setup();
    const response = await call("/api/agent/actions/get-session", '{"x":1.5}');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      principal: { id: "agent_a", type: "agent", display_name: "Agent A" },
      server: { id: "srv_a", slug: "a", name: "Server A" },
      session_expires_at: expiresAt,
    });
    for (const body of ["", "[]", "not json"]) {
      const bad = await call("/api/agent/actions/get-session", body);
      expect(bad.status).toBe(400);
      expect(await bad.json()).toEqual({ error: "invalid_request", hint: "The request body must be a JSON object." });
    }
    for (let i = 1; i < 120; i++) expect((await call("/api/agent/actions/get-session", "{}")).status).toBe(200);
    const limited = await call("/api/agent/actions/get-session", "{}");
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
    expect(Number(limited.headers.get("Retry-After"))).toBeLessThanOrEqual(60);
    expect(await limited.json()).toEqual({ error: "rate_limited", hint: "Read limit exceeded; retry after the indicated delay." });
    expect(sqlite.prepare("SELECT action, units, COUNT(*) AS n FROM rate_reservations GROUP BY action, units").all().map((row) => ({ ...row })))
      .toEqual([{ action: "read", units: 1, n: 120 }]);
  });

  it("register_key end to end: 201 stored in D1, 200 on repeat, oversize is 400 invalid_request", async () => {
    const { call, sqlite } = setup();
    const key = await agentKey();
    const body = await registrationBody(key, statementFor(key, { issued_at: new Date().toISOString() }));
    const created = await call("/api/agent/actions/register-key", body);
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({ key_id: key.keyId, status: "active", server: { id: "srv_a", slug: "a" }, principal: { id: "agent_a", type: "agent" } });
    expect((await call("/api/agent/actions/register-key", body)).status).toBe(200);
    expect(sqlite.prepare("SELECT key_id, server_id, principal_id, revoked_at FROM keys").all().map((row) => ({ ...row })))
      .toEqual([{ key_id: key.keyId, server_id: "srv_a", principal_id: "agent_a", revoked_at: null }]);

    const oversize = await call("/api/agent/actions/register-key", new Uint8Array(65_537));
    expect(oversize.status).toBe(400);
    expect(await oversize.json()).toEqual({ error: "invalid_request", hint: "Request body exceeds 64 KB." });
  });

  it("list_keys and revoke_key end to end", async () => {
    const { call, sqlite } = setup();
    const key = await agentKey();
    expect((await call("/api/agent/actions/register-key", await registrationBody(key, statementFor(key, { issued_at: new Date().toISOString() })))).status).toBe(201);
    const revoked = await call("/api/agent/actions/revoke-key", JSON.stringify({ key_id: key.keyId, reason: "compromised" }));
    expect(revoked.status).toBe(200);
    const record = await revoked.json() as Record<string, unknown>;
    expect(record).toMatchObject({ key_id: key.keyId, status: "revoked", revoked_reason: "compromised", compromised_since: record.registered_at });
    const listed = await call("/api/agent/actions/list-keys", "{}");
    expect(await listed.json()).toEqual({ keys: [record] });
    expect(sqlite.prepare("SELECT action, COUNT(*) AS n FROM rate_reservations GROUP BY action ORDER BY action").all().map((row) => ({ ...row })))
      .toEqual([{ action: "read", n: 1 }, { action: "register", n: 1 }, { action: "revoke", n: 1 }]);
  });

  it("submit_receipt step 1: over 64 KB is 413 receipt_too_large even with no cookie, so size runs before the session", async () => {
    const { call } = setup();
    for (const cookie of [null, `cc_session=${RAW_ID}`]) {
      const response = await call("/api/agent/actions/submit-receipt", new Uint8Array(65_537), cookie);
      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({ error: "receipt_too_large", hint: "The request body exceeds 64 KB." });
    }
    // Exactly 64 KB passes step 1 and stops at step 2 without a cookie.
    expect((await call("/api/agent/actions/submit-receipt", `${" ".repeat(65_534)}{}`, null)).status).toBe(401);
  });

  it("submit_receipt steps 2 and 3: 401 without a session, 403 for a blocked server, before the body is parsed", async () => {
    const { call, sqlite } = setup();
    for (const cookie of [null, `cc_session=${"cd".repeat(32)}`]) {
      const response = await call("/api/agent/actions/submit-receipt", "not json", cookie);
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ error: "not_authenticated" });
    }
    sqlite.prepare("UPDATE sessions SET scopes = 'openid'").run();
    expect((await call("/api/agent/actions/submit-receipt", "not json")).status).toBe(401);
    sqlite.prepare("UPDATE sessions SET scopes = 'openid profile'").run();
    sqlite.prepare("INSERT INTO blocked_servers (server_id, blocked_at, reason) VALUES ('srv_a', '2026-10-06T00:00:00.000Z', 'test')").run();
    const blocked = await call("/api/agent/actions/submit-receipt", "not json");
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ error: "not_authorized" });
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM rate_reservations").get()).toEqual({ n: 0 });
  });

  it("submit_receipt end to end: 201 stored in D1 as JCS, 200 duplicate on resubmission", async () => {
    const { call, sqlite } = setup();
    const key = await agentKey();
    const now = Date.now();
    expect((await call("/api/agent/actions/register-key", await registrationBody(key, statementFor(key, { issued_at: new Date(now).toISOString() })))).status).toBe(201);
    const payload = runPayload(key, { signed_at: new Date(now).toISOString() }, { started_at: new Date(now - 3000).toISOString(), finished_at: new Date(now - 10).toISOString() });
    const body = await receiptBody(key, payload);
    const created = await call("/api/agent/actions/submit-receipt", body);
    expect(created.status).toBe(201);
    const receipt = await created.json() as { receipt_id: string; envelope: unknown; duplicate: boolean };
    expect(receipt.receipt_id).toBe(await receiptId(payload as never));
    expect(receipt.duplicate).toBe(false);
    expect(sqlite.prepare("SELECT id, key_id, kind, envelope_json FROM receipts").all().map((row) => ({ ...row })))
      .toEqual([{ id: receipt.receipt_id, key_id: key.keyId, kind: "run", envelope_json: canonicalize(receipt.envelope) }]);
    const again = await call("/api/agent/actions/submit-receipt", body);
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ receipt_id: receipt.receipt_id, duplicate: true });
  });

  it("answers unknown routes and methods with 404", async () => {
    const { env } = setup();
    const response = await worker.fetch(new Request(`${ORIGIN}/api/agent/actions/get-session`, { method: "GET" }), env);
    expect(response.status).toBe(404);
  });
});
