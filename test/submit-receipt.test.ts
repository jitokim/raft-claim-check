// submit_receipt, steps 4 to 13 of ## Verification, on the in-memory store. Steps 1 to 3 run in the router (router.test.ts).
import { describe, it, expect } from "vitest";
import { receiptId } from "../src/crypto";
import { canonicalize } from "../src/jcs";
import { submitReceipt } from "../src/receipts";
import type { KeyRow } from "../src/store";
import {
  agentKey, attestPayload, bindKey, DAY, encode, harness, iso, MINUTE, receiptBody, runPayload, session, T0, type AgentKey, type Statement,
} from "./helpers";
import { MemoryStore } from "./memory-store";

const ESC = String.fromCharCode(0x1b);
// Far enough ahead to fail the 5-minute clock_skew bound.
const HOUR_PLUS = 61 * MINUTE;

const expectError = (result: { status: number; body: Record<string, unknown> }, status: number, code: string) => {
  expect(result.status).toBe(status);
  expect(result.body).toEqual({ error: code, hint: expect.any(String) });
};

/** A fresh store with one key bound to srv_a/agent_a. */
async function setup(now = T0) {
  const { store, call } = harness({ now });
  const key = await agentKey();
  await bindKey(store, key);
  return { store, key, submit: (body: Uint8Array, overrides: Parameters<typeof call>[2] = {}) => call(submitReceipt, body, overrides) };
}

/** Replaces one exact piece of a JSON body's text, for bodies JSON.stringify cannot produce (duplicate keys, 1.0). */
const rewrite = (body: Uint8Array, from: string, to: string) => {
  const text = new TextDecoder().decode(body);
  expect(text).toContain(from);
  return encode(text.replace(from, to));
};

describe("submit_receipt", () => {
  it("13. stores a new run receipt and returns 201 with receipt_id, envelope and ledger", async () => {
    const { store, key, submit } = await setup();
    const payload = runPayload(key);
    const body = await receiptBody(key, payload);
    const result = await submit(body);
    expect(result.status).toBe(201);
    const id = await receiptId(payload as never);
    const envelope = (JSON.parse(new TextDecoder().decode(body)) as { receipt: Statement }).receipt;
    expect(result.body).toEqual({
      receipt_id: id,
      envelope,
      ledger: {
        received_at: iso(T0),
        expires_at: iso(T0 + 90 * DAY),
        server: { id: "srv_a", slug: "a" },
        submitted_by: { principal_id: "agent_a", principal_type: "agent" },
        key: { key_id: key.keyId, public_key: key.publicKey, status: "active", revoked_at: null, compromised_window: false },
        submitted_late: false,
        acceptance_surface: `Exit status and output of argv [go test ./...] in the recorded git checkout, on the machine holding key ${key.keyId}`,
        verified: [
          `signature valid over JCS(payload) for key ${key.keyId}`,
          `key registered with proof of possession, bound to server srv_a and principal agent_a, active at received_at`,
          "submitted by principal agent_a through its Claim Check session",
          "received_at from the app's clock",
          "schema and consistency checks passed",
        ],
        asserted: ["run.*", "git.*", "cli.*", "signed_at"],
        proved: [
          `The holder of key ${key.keyId}, bound to principal agent_a on server srv_a, signed this exact record, and it reached the ledger at ${iso(T0)} while ${key.keyId} was active`,
          "Asserted by the key holder: argv ran with HEAD 0123456789abcdef0123456789abcdef01234567 and dirty flag false, exited with code 0, and produced output whose full bytes hash to the recorded digests",
        ],
        not_proved: [
          "That the CLI was unmodified, or that the command ran at all; everything in payload is asserted by the key holder",
          "That the command checks what the claim is about",
          "That git.head is pushed, reviewed, merged or deployed, or that a dirty: true tree contained anything in particular",
          "That the environment, inputs, network or time matched any other run, or that the result is reproducible",
          "That this was the only attempt; the CLI submits every run, but a lying owner can withhold the red ones",
          "Anything after finished_at",
        ],
      },
      duplicate: false,
    });
    expect(store.receipts).toHaveLength(1);
    const [row] = store.receipts;
    expect(row).toMatchObject({
      id, server_id: "srv_a", principal_id: "agent_a", principal_type: "agent", key_id: key.keyId, kind: "run",
      signed_at: iso(T0), received_at: iso(T0), expires_at: iso(T0 + 90 * DAY), envelope_json: canonicalize(envelope),
    });
    expect(JSON.parse(row.ledger_json)).toEqual((result.body as { ledger: unknown }).ledger);
  });

  it("13. stores an attest receipt with the attest form of the ledger", async () => {
    const { key, submit } = await setup();
    const result = await submit(await receiptBody(key, attestPayload(key)));
    expect(result.status).toBe(201);
    expect(result.body.ledger).toMatchObject({
      acceptance_surface: `The bytes of the file dist/widgets.tar.gz on the machine holding key ${key.keyId}`,
      asserted: ["attest.*", "git.*", "cli.*", "signed_at"],
      proved: [expect.any(String), `Asserted by the key holder: at ${iso(T0 - 1000)}, the file at dist/widgets.tar.gz had SHA-256 sha256:${"cd".repeat(32)} and size 4096`],
      not_proved: ["That the file is the output of any particular command or commit", "That it is the file that was shipped, uploaded or deployed", "That its contents are correct"],
    });
  });

  it("13. describes a signal-terminated run outside a repository", async () => {
    const { key, submit } = await setup();
    const payload = runPayload(key, { git: null }, { cwd_rel: null, exit: { code: null, signal: "SIGKILL" } });
    const result = await submit(await receiptBody(key, payload));
    expect(result.status).toBe(201);
    expect(result.body.ledger).toMatchObject({
      acceptance_surface: `Exit status and output of argv [go test ./...] outside any git repository, on the machine holding key ${key.keyId}`,
      proved: [expect.any(String), "Asserted by the key holder: argv ran outside any git repository, was terminated by signal SIGKILL, and produced output whose full bytes hash to the recorded digests"],
    });
  });

  it("12. a resubmitted payload returns 200 with the stored receipt and duplicate true, and still uses a reservation", async () => {
    const { store, key, submit } = await setup();
    const payload = runPayload(key);
    const first = await submit(await receiptBody(key, payload));
    // A later resubmission (from the spool, say) with the same payload: same ID, same stored ledger.
    const again = await submit(await receiptBody(key, payload), { now: T0 + 2 * MINUTE });
    expect(again.status).toBe(200);
    const { duplicate: _created, ...stored } = first.body;
    expect(again.body).toEqual({ ...stored, duplicate: true });
    expect(store.receipts).toHaveLength(1);
    expect(store.reservations).toHaveLength(2);
  });

  it("4. invalid_request for a bad shape or duplicate keys, without using a reservation", async () => {
    const { store, key, submit } = await setup();
    const valid = await receiptBody(key, runPayload(key));
    const envelope = (JSON.parse(new TextDecoder().decode(valid)) as { receipt: Statement }).receipt;
    const bodies = [
      encode(""), encode("not json"), encode("[]"), encode("{}"), encode({ receipt: "x" }), encode({ receipt: [] }),
      encode({ receipt: { signature: envelope.signature } }), encode({ receipt: { payload: envelope.payload } }),
      encode({ receipt: { payload: "x", signature: envelope.signature } }), encode({ receipt: { payload: envelope.payload, signature: null } }),
      encode({ receipt: envelope, extra: 1 }), encode({ receipt: { ...envelope, ledger: {} } }),
      encode({ receipt: { ...envelope, signature: { ...(envelope.signature as Statement), note: "x" } } }),
      rewrite(valid, '{"receipt":{', '{"receipt":{"payload":{},'),
      rewrite(valid, '"kind":"run"', '"kind":"run","kind":"run"'),
      rewrite(valid, '"code":0', '"code":0,"code":0'),
    ];
    for (const body of bodies) expectError(await submit(body), 400, "invalid_request");
    expect(store.reservations).toHaveLength(0);
  });

  it("5. 429 with Retry-After once 30 submissions are used in a minute, and nothing is stored", async () => {
    const { store, key, submit } = await setup();
    for (let i = 0; i < 30; i++) expect((await submit(await receiptBody(key, runPayload(key)), { now: T0 + i })).status).toBe(201);
    const limited = await submit(await receiptBody(key, runPayload(key)), { now: T0 + 30_000 });
    expectError(limited, 429, "rate_limited");
    expect(limited.headers.get("Retry-After")).toBe("30");
    expect(store.receipts).toHaveLength(30);
    expect(store.reservations).toHaveLength(30);
  });

  it("6. schema_unsupported for another schema or kind", async () => {
    const { store, key, submit } = await setup();
    for (const overrides of [{ schema: "claim-check.receipt.v1" }, { schema: "claim-check.key-registration.v2" }, { schema: undefined }, { kind: "exec" }, { kind: undefined }, { kind: 1 }]) {
      expectError(await submit(await receiptBody(key, runPayload(key, overrides))), 400, "schema_unsupported");
    }
    expect(store.receipts).toHaveLength(0);
  });

  it("7. binding_mismatch for another server or principal, a missing bound_to, or key_id disagreement", async () => {
    const { key, submit } = await setup();
    const other = await agentKey();
    const cases: [Statement, Statement][] = [
      [{ bound_to: { server_id: "srv_b", principal_id: "agent_a" } }, {}],
      [{ bound_to: { server_id: "srv_a", principal_id: "agent_b" } }, {}],
      [{ bound_to: undefined }, {}],
      [{ bound_to: null }, {}],
      [{ bound_to: { server_id: "srv_a" } }, {}],
      [{}, { key_id: other.keyId }],
      [{}, { key_id: undefined }],
      [{ key_id: 7 }, { key_id: 7 }],
      [{ key_id: undefined }, { key_id: undefined }],
    ];
    for (const [overrides, signature] of cases) expectError(await submit(await receiptBody(key, runPayload(key, overrides), signature)), 400, "binding_mismatch");
  });

  it("8. key_not_registered with the identical body for an unknown key and a key bound elsewhere; key_revoked for a revoked key", async () => {
    const { store, key, submit } = await setup();
    const unknown = await agentKey();
    const elsewhere = await agentKey();
    await bindKey(store, elsewhere, { principal_id: "agent_b" });
    const otherServer = await agentKey();
    await bindKey(store, otherServer, { server_id: "srv_b" });
    const responses = [];
    for (const signer of [unknown, elsewhere, otherServer]) {
      const result = await submit(await receiptBody(signer, runPayload(signer)));
      expectError(result, 403, "key_not_registered");
      responses.push(result.body);
    }
    expect(responses[1]).toEqual(responses[0]);
    expect(responses[2]).toEqual(responses[0]);

    await store.revokeKey({ keyId: key.keyId, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(T0 - MINUTE), reason: "rotated", compromisedSince: null });
    expectError(await submit(await receiptBody(key, runPayload(key))), 403, "key_revoked");
    expect(store.receipts).toHaveLength(0);
  });

  it("9. bad_signature for a tampered payload, another key's signature, a wrong alg and non-canonical encodings", async () => {
    const { store, key, submit } = await setup();
    const other = await agentKey();
    const payload = runPayload(key);
    const value = await key.sign(payload);
    const body = (changes: { payload?: Statement; signature?: Statement }) =>
      encode({ receipt: { payload: { ...payload, ...changes.payload }, signature: { alg: "ed25519", key_id: key.keyId, value, ...changes.signature } } });
    const faults = [
      body({ payload: { nonce: "AAAAAAAAAAAAAAAAAAAAAA" } }),
      body({ payload: { signed_at: iso(T0 - 1) } }),
      body({ signature: { value: await other.sign(payload) } }),
      body({ signature: { alg: "Ed25519" } }),
      body({ signature: { alg: undefined } }),
      body({ signature: { value: undefined } }),
      body({ signature: { value: 5 } }),
      body({ signature: { value: value.slice("ed25519:".length) } }),
      body({ signature: { value: `${value}=` } }),
      body({ signature: { value: `ed25519:${"A".repeat(86)}` } }),
    ];
    for (const fault of faults) expectError(await submit(fault), 400, "bad_signature");
    // The unmodified envelope is fine, so each fault above is what failed.
    expect((await submit(body({}))).status).toBe(201);
    expect(store.receipts).toHaveLength(1);
  });

  describe("10. schema_invalid, with a hint naming the field", () => {
    const longText = (bytes: number) => "x".repeat(bytes);
    const cases: [string, (key: AgentKey) => Statement, string][] = [
      ["run absent", (key) => runPayload(key, { run: undefined }), "payload.run"],
      ["attest present on a run", (key) => runPayload(key, { attest: attestPayload(key).attest }), "payload.run"],
      ["run present on an attest", (key) => attestPayload(key, { run: runPayload(key).run }), "payload.attest"],
      ["unknown payload field", (key) => runPayload(key, { extra: true }), "payload has an unknown field \"extra\""],
      ["nonce not 16 bytes", (key) => runPayload(key, { nonce: "AAAA" }), "payload.nonce"],
      ["nonce not base64url", (key) => runPayload(key, { nonce: "AAAAAAAAAAAAAAAAAAAAA+" }), "payload.nonce"],
      ["bound_to extra member", (key) => runPayload(key, { bound_to: { server_id: "srv_a", principal_id: "agent_a", x: 1 } }), "payload.bound_to"],
      ["cli.name", (key) => runPayload(key, { cli: { name: "other", version: "1", os: "linux", arch: "amd64" } }), "payload.cli.name"],
      ["cli.version missing", (key) => runPayload(key, { cli: { name: "claim-check", os: "linux", arch: "amd64" } }), "payload.cli.version"],
      ["cli.os over 1 KB", (key) => runPayload(key, { cli: { name: "claim-check", version: "1", os: longText(1025), arch: "amd64" } }), "payload.cli.os"],
      ["signed_at without milliseconds", (key) => runPayload(key, { signed_at: "2026-10-06T09:00:00Z" }), "payload.signed_at"],
      ["git.head short", (key) => runPayload(key, { git: { remote_url: null, head: "abc", branch: null, dirty: false } }), "payload.git.head"],
      ["git.dirty not boolean", (key) => runPayload(key, { git: { remote_url: null, head: null, branch: null, dirty: "no" } }), "payload.git.dirty"],
      ["git.remote_url with userinfo", (key) => runPayload(key, { git: { remote_url: "https://u:p@example.com/r.git", head: null, branch: null, dirty: false } }), "payload.git.remote_url"],
      ["argv empty", (key) => runPayload(key, {}, { argv: [] }), "payload.run.argv"],
      ["argv over 128 elements", (key) => runPayload(key, {}, { argv: Array(129).fill("a") }), "payload.run.argv"],
      ["argv over 8 KB", (key) => runPayload(key, {}, { argv: Array(9).fill(longText(1000)) }), "payload.run.argv"],
      ["argv element over 1 KB", (key) => runPayload(key, {}, { argv: ["go", longText(1025)] }), "payload.run.argv[1]"],
      ["argv element not a string", (key) => runPayload(key, {}, { argv: ["go", 1] }), "payload.run.argv[1]"],
      ["argv_redactions above argv length", (key) => runPayload(key, {}, { argv_redactions: 4 }), "payload.run.argv_redactions"],
      ["cwd_rel absolute", (key) => runPayload(key, {}, { cwd_rel: "/home/agent/repo" }), "payload.run.cwd_rel"],
      ["cwd_rel escaping the repository", (key) => runPayload(key, {}, { cwd_rel: "a/../.." }), "payload.run.cwd_rel"],
      ["cwd_rel set outside a repository", (key) => runPayload(key, { git: null }), "payload.run.cwd_rel"],
      ["started_at after finished_at", (key) => runPayload(key, {}, { started_at: iso(T0 - 5), finished_at: iso(T0 - 10) }), "payload.run.started_at"],
      ["finished_at after signed_at", (key) => runPayload(key, {}, { finished_at: iso(T0 + 1) }), "payload.run.finished_at"],
      ["duration_ms negative", (key) => runPayload(key, {}, { duration_ms: -1 }), "payload.run.duration_ms"],
      ["exit with both", (key) => runPayload(key, {}, { exit: { code: 1, signal: "SIGTERM" } }), "payload.run.exit"],
      ["exit with neither", (key) => runPayload(key, {}, { exit: { code: null, signal: null } }), "payload.run.exit"],
      ["exit.code out of range", (key) => runPayload(key, {}, { exit: { code: 256, signal: null } }), "payload.run.exit.code"],
      ["stdout.sha256 uppercase", (key) => runPayload(key, {}, { stdout: { sha256: `sha256:${"AB".repeat(32)}`, bytes: 1, tail: "x", tail_truncated: false, tail_redactions: 0 } }), "payload.run.stdout.sha256"],
      ["stdout.tail over 2048 bytes", (key) => runPayload(key, {}, { stdout: { sha256: `sha256:${"ab".repeat(32)}`, bytes: 9000, tail: longText(2049), tail_truncated: true, tail_redactions: 0 } }), "payload.run.stdout.tail"],
      ["stdout.tail with an escape", (key) => runPayload(key, {}, { stdout: { sha256: `sha256:${"ab".repeat(32)}`, bytes: 9, tail: `${ESC}[31mred`, tail_truncated: false, tail_redactions: 0 } }), "payload.run.stdout.tail"],
      ["stderr tail on an empty stream", (key) => runPayload(key, {}, { stderr: { sha256: `sha256:${"ab".repeat(32)}`, bytes: 0, tail: "x", tail_truncated: false, tail_redactions: 0 } }), "payload.run.stderr"],
      ["stderr missing a member", (key) => runPayload(key, {}, { stderr: { sha256: `sha256:${"ab".repeat(32)}`, bytes: 0, tail: "", tail_truncated: false } }), "payload.run.stderr.tail_redactions"],
      ["attest.path absolute", (key) => attestPayload(key, { attest: { ...(attestPayload(key).attest as Statement), path: "/etc/passwd" } }), "payload.attest.path"],
      ["attest.path not a base name outside a repository", (key) => attestPayload(key, { git: null }), "payload.attest.path"],
      ["attest.observed_at after signed_at", (key) => attestPayload(key, { attest: { ...(attestPayload(key).attest as Statement), observed_at: iso(T0 + 1) } }), "payload.attest.observed_at"],
      ["attest.bytes not an integer", (key) => attestPayload(key, { attest: { ...(attestPayload(key).attest as Statement), bytes: "4096" } }), "payload.attest.bytes"],
    ];

    it.each(cases)("%s", async (_name, build, field) => {
      const { store, key, submit } = await setup();
      const result = await submit(await receiptBody(key, build(key)));
      expectError(result, 400, "schema_invalid");
      expect(result.body.hint).toContain(field);
      expect(store.receipts).toHaveLength(0);
    });

    it("refuses floats even when correctly signed: 1.5, and 1.0 whose value is integral", async () => {
      const { key, submit } = await setup();
      const half = await submit(await receiptBody(key, runPayload(key, {}, { duration_ms: 1.5 })));
      expectError(half, 400, "schema_invalid");
      expect(half.body.hint).toContain("payload.run.duration_ms");
      // 2990.0 parses to the value 2990, so the signature over JCS (which writes 2990) verifies; the literal is still a float.
      const one = await submit(rewrite(await receiptBody(key, runPayload(key)), '"duration_ms":2990', '"duration_ms":2990.0'), { now: T0 + 1 });
      expectError(one, 400, "schema_invalid");
      expect(one.body.hint).toContain("payload.run.duration_ms");
      const exponent = await submit(rewrite(await receiptBody(key, runPayload(key)), '"argv_redactions":0', '"argv_redactions":0e0'), { now: T0 + 2 });
      expect(exponent.body.hint).toContain("payload.run.argv_redactions");
    });

    it("refuses integers outside +/-2^53 and -0", async () => {
      const { key, submit } = await setup();
      // 2^53 + 2 is exactly representable, so it is signed and parsed as the same value.
      const stdout = { sha256: `sha256:${"ab".repeat(32)}`, bytes: 2 ** 53 + 2, tail: "", tail_truncated: true, tail_redactions: 0 };
      const big = await submit(await receiptBody(key, runPayload(key, {}, { stdout })));
      expectError(big, 400, "schema_invalid");
      expect(big.body.hint).toContain("payload.run.stdout.bytes");
      const negativeZero = await submit(rewrite(await receiptBody(key, runPayload(key)), '"code":0', '"code":-0'), { now: T0 + 1 });
      expectError(negativeZero, 400, "schema_invalid");
      expect(negativeZero.body.hint).toContain("payload.run.exit.code");
    });

    it("accepts the caps exactly: 128 argv elements, 8 KB argv, a 2048-byte tail, 1 KB strings", async () => {
      const { key, submit } = await setup();
      const accepted = [
        runPayload(key, {}, { argv: Array(128).fill("a") }),
        runPayload(key, {}, { argv: [...Array(8).fill(longText(1000)), longText(192)] }),
        runPayload(key, {}, { stdout: { sha256: `sha256:${"ab".repeat(32)}`, bytes: 9000, tail: longText(2048), tail_truncated: true, tail_redactions: 0 } }),
        runPayload(key, { cli: { name: "claim-check", version: longText(1024), os: "linux", arch: "amd64" } }),
      ];
      for (const [index, payload] of accepted.entries()) expect((await submit(await receiptBody(key, payload), { now: T0 + index })).status).toBe(201);
    });
  });

  it("11. clock_skew beyond 5 minutes ahead and receipt_too_old beyond 7 days; both bounds are inclusive", async () => {
    const { key, submit } = await setup();
    // run.started_at and finished_at must not follow signed_at, so the run times move with it.
    const signedAt = (ms: number) => runPayload(key, { signed_at: iso(ms) }, { started_at: iso(ms - 2), finished_at: iso(ms - 1) });
    expectError(await submit(await receiptBody(key, signedAt(T0 + 5 * MINUTE + 1))), 400, "clock_skew");
    expectError(await submit(await receiptBody(key, signedAt(T0 - 7 * DAY - 1))), 400, "receipt_too_old");
    expect((await submit(await receiptBody(key, signedAt(T0 + 5 * MINUTE)))).status).toBe(201);
    const accepted = await submit(await receiptBody(key, signedAt(T0 - 7 * DAY)));
    expect(accepted.status).toBe(201);
    expect(accepted.body.ledger).toMatchObject({ submitted_late: true });
  });

  it("11. submitted_late only when signed more than 10 minutes before received_at", async () => {
    const { key, submit } = await setup();
    const onTime = await submit(await receiptBody(key, runPayload(key)), { now: T0 + 10 * MINUTE });
    expect(onTime.body.ledger).toMatchObject({ submitted_late: false });
    const late = await submit(await receiptBody(key, runPayload(key)), { now: T0 + 10 * MINUTE + 1 });
    expect(late.body.ledger).toMatchObject({ submitted_late: true, received_at: iso(T0 + 10 * MINUTE + 1) });
  });

  describe("order: the earlier step's code wins", () => {
    it("binding mismatch plus bad signature gives binding_mismatch", async () => {
      const { key, submit } = await setup();
      const other = await agentKey();
      expectError(await submit(await receiptBody(key, runPayload(key, { bound_to: { server_id: "srv_b", principal_id: "agent_a" } }), {}, other)), 400, "binding_mismatch");
    });

    it("revoked key plus bad signature gives key_revoked", async () => {
      const { store, key, submit } = await setup();
      const other = await agentKey();
      await store.revokeKey({ keyId: key.keyId, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(T0 - MINUTE), reason: "lost", compromisedSince: null });
      expectError(await submit(await receiptBody(key, runPayload(key), {}, other)), 403, "key_revoked");
    });

    it("bad signature plus clock skew gives bad_signature", async () => {
      const { key, submit } = await setup();
      const other = await agentKey();
      expectError(await submit(await receiptBody(key, runPayload(key, { signed_at: iso(T0 + HOUR_PLUS) }), {}, other)), 400, "bad_signature");
    });

    it("schema_invalid plus clock skew gives schema_invalid", async () => {
      const { key, submit } = await setup();
      expectError(await submit(await receiptBody(key, runPayload(key, { signed_at: iso(T0 + HOUR_PLUS), nonce: "short" }))), 400, "schema_invalid");
    });

    it("rate-limited plus bad signature gives 429", async () => {
      const { key, submit } = await setup();
      const other = await agentKey();
      for (let i = 0; i < 30; i++) expect((await submit(await receiptBody(key, runPayload(key)), { now: T0 + i })).status).toBe(201);
      expectError(await submit(await receiptBody(key, runPayload(key), {}, other), { now: T0 + 30 }), 429, "rate_limited");
    });

    it("schema_unsupported comes before binding_mismatch, and binding_mismatch before key_not_registered", async () => {
      const { submit } = await setup();
      const unknown = await agentKey();
      expectError(await submit(await receiptBody(unknown, runPayload(unknown, { kind: "exec", bound_to: null }))), 400, "schema_unsupported");
      expectError(await submit(await receiptBody(unknown, runPayload(unknown, { bound_to: null }))), 400, "binding_mismatch");
    });
  });

  it("uses the session's identity: another principal on the same server cannot submit with agent_a's key", async () => {
    const { key, submit } = await setup();
    const payload = runPayload(key, { bound_to: { server_id: "srv_a", principal_id: "agent_b" } });
    expectError(await submit(await receiptBody(key, payload), { session: session({ principal_id: "agent_b" }) }), 403, "key_not_registered");
  });

  describe("revoke_key racing submit_receipt", () => {
    /** Returns the still-active key row from getBoundKey (step 8), then revokes the key, as if revoke_key committed during step 9. */
    class RevokingStore extends MemoryStore {
      revokeOnLookup = false;
      override async getBoundKey(keyId: string, serverId: string, principalId: string): Promise<KeyRow | null> {
        const row = await super.getBoundKey(keyId, serverId, principalId);
        if (this.revokeOnLookup) {
          expect(row?.revoked_at).toBeNull();
          expect(await this.revokeKey({ keyId, serverId, principalId, revokedAt: iso(T0 - 1), reason: "lost", compromisedSince: null })).toBe(true);
        }
        return row;
      }
    }

    async function raceSetup() {
      const store = new RevokingStore();
      const { call } = harness({ store });
      const key = await agentKey();
      await bindKey(store, key);
      return { store, key, submit: (body: Uint8Array) => call(submitReceipt, body) };
    }

    const revoke = (store: MemoryStore, key: AgentKey) =>
      store.revokeKey({ keyId: key.keyId, serverId: "srv_a", principalId: "agent_a", revokedAt: iso(T0 - MINUTE), reason: "lost", compromisedSince: null });

    it("12. a key revoked between lookup and insert gives 403 key_revoked and stores nothing", async () => {
      const { store, key, submit } = await raceSetup();
      store.revokeOnLookup = true;
      expectError(await submit(await receiptBody(key, runPayload(key))), 403, "key_revoked");
      expect(store.keys[0].revoked_at).not.toBeNull();
      expect(store.receipts).toHaveLength(0);
    });

    it("12. the same race for an already stored receipt returns 200 duplicate true with the stored receipt", async () => {
      const { store, key, submit } = await raceSetup();
      const body = await receiptBody(key, runPayload(key));
      const first = await submit(body);
      expect(first.status).toBe(201);
      store.revokeOnLookup = true;
      const again = await submit(body);
      expect(store.keys[0].revoked_at).not.toBeNull();
      expect(again.status).toBe(200);
      const { duplicate: _created, ...stored } = first.body;
      // The stored receipt is returned as is, except that ledger.key shows the key's current (revoked) status.
      const ledger = stored.ledger as { key: Record<string, unknown> };
      expect(again.body).toEqual({
        ...stored, duplicate: true,
        ledger: { ...ledger, key: { ...ledger.key, status: "revoked", revoked_at: store.keys[0].revoked_at } },
      });
      expect(store.receipts).toHaveLength(1);
    });

    it("8. resubmitting a stored receipt after its key was revoked returns 200 duplicate true", async () => {
      const { store, key, submit } = await setup();
      const body = await receiptBody(key, runPayload(key));
      const first = await submit(body);
      expect(first.status).toBe(201);
      expect(await revoke(store, key)).toBe(true);
      const again = await submit(body);
      expect(again.status).toBe(200);
      expect(again.body.duplicate).toBe(true);
      expect(again.body.receipt_id).toBe(first.body.receipt_id);
      expect(store.receipts).toHaveLength(1);
    });

    it("8. a first submit with an already revoked key gives 403 key_revoked and stores nothing", async () => {
      const { store, key, submit } = await setup();
      expect(await revoke(store, key)).toBe(true);
      expectError(await submit(await receiptBody(key, runPayload(key))), 403, "key_revoked");
      expect(store.receipts).toHaveLength(0);
    });
  });
});
