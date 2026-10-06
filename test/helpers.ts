import type { ActionContext, ActionHandler, Session } from "../src/context";
import { keyId } from "../src/crypto";
import { canonicalize } from "../src/jcs";
import type { NewKey } from "../src/store";
import { MemoryStore } from "./memory-store";

export const T0 = Date.UTC(2026, 9, 6, 9, 0, 0);
export const MINUTE = 60_000;
export const HOUR = 3_600_000;
export const iso = (ms: number) => new Date(ms).toISOString();

export const session = (overrides: Partial<Session> = {}): Session => ({
  id_hash: "hash", server_id: "srv_a", server_slug: "a", server_name: "A", principal_id: "agent_a", principal_type: "agent",
  display_name: null, scopes: "openid profile", expires_at: "2026-10-07T09:00:00.000Z", ...overrides,
});

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export interface AgentKey { publicKey: string; keyId: string; sign(payload: unknown): Promise<string> }

/** A fresh ed25519 keypair from WebCrypto; sign() signs the UTF-8 JCS form of a payload. */
export async function agentKey(): Promise<AgentKey> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey) as ArrayBuffer);
  return {
    publicKey: `ed25519:${b64url(raw)}`,
    keyId: await keyId(raw),
    // "finite" lets a test sign a payload holding a float, to show that step 10 (not step 9) refuses it.
    sign: async (payload) => `ed25519:${b64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(canonicalize(payload, "finite")))))}`,
  };
}

export type Statement = Record<string, unknown>;

export function statementFor(key: AgentKey, overrides: Statement = {}): Statement {
  return {
    schema: "claim-check.key-registration.v2", public_key: key.publicKey, key_id: key.keyId, server_id: "srv_a", principal_id: "agent_a",
    issued_at: iso(T0), nonce: b64url(crypto.getRandomValues(new Uint8Array(16))), label: "laptop", cli_version: "2.0.0", ...overrides,
  };
}

export const encode = (value: unknown) => new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value));

/** {registration: {payload, signature}} signed by `signer` (default: the statement's own key). */
export async function registrationBody(key: AgentKey, payload: Statement, signature: Statement = {}, signer: AgentKey = key): Promise<Uint8Array> {
  return encode({ registration: { payload, signature: { alg: "ed25519", key_id: payload.key_id, value: await signer.sign(payload), ...signature } } });
}

export const DAY = 86_400_000;

/** Stores `key` as an active key of agent_a on srv_a (or the given binding), registered a day before T0. */
export async function bindKey(store: MemoryStore, key: AgentKey, overrides: Partial<NewKey> = {}): Promise<void> {
  await store.insertKey({
    key_id: key.keyId, public_key: key.publicKey, server_id: "srv_a", principal_id: "agent_a", principal_type: "agent", label: null,
    registered_at: iso(T0 - DAY), ...overrides,
  }, 5);
}

const stream = (overrides: Statement = {}): Statement => ({
  sha256: `sha256:${"ab".repeat(32)}`, bytes: 18, tail: "ok  \texample\t1.2s\n", tail_truncated: false, tail_redactions: 0, ...overrides,
});

/** A valid run payload for `key`, bound to srv_a/agent_a and signed at T0. `run` overrides are merged into payload.run. */
export function runPayload(key: AgentKey, overrides: Statement = {}, run: Statement = {}): Statement {
  return {
    schema: "claim-check.receipt.v2", kind: "run", nonce: b64url(crypto.getRandomValues(new Uint8Array(16))), key_id: key.keyId,
    bound_to: { server_id: "srv_a", principal_id: "agent_a" },
    cli: { name: "claim-check", version: "2.0.0", os: "darwin", arch: "arm64" },
    signed_at: iso(T0),
    git: { remote_url: "https://github.com/example/widgets.git", head: "0123456789abcdef0123456789abcdef01234567", branch: "main", dirty: false },
    run: {
      argv: ["go", "test", "./..."], argv_redactions: 0, cwd_rel: ".", started_at: iso(T0 - 3000), finished_at: iso(T0 - 10), duration_ms: 2990,
      exit: { code: 0, signal: null }, stdout: stream(), stderr: stream({ bytes: 0, tail: "" }), ...run,
    },
    ...overrides,
  };
}

/** A valid attest payload for `key`, signed at T0. */
export function attestPayload(key: AgentKey, overrides: Statement = {}): Statement {
  const { run: _run, ...base } = runPayload(key);
  return {
    ...base, kind: "attest",
    attest: { path: "dist/widgets.tar.gz", sha256: `sha256:${"cd".repeat(32)}`, bytes: 4096, observed_at: iso(T0 - 1000) },
    ...overrides,
  };
}

/** {receipt: {payload, signature}} signed by `signer` (default: `key`). Members set to undefined are dropped, as on the wire. */
export async function receiptBody(key: AgentKey, payload: Statement, signature: Statement = {}, signer: AgentKey = key): Promise<Uint8Array> {
  const sent = JSON.parse(JSON.stringify(payload)) as Statement;
  return encode({ receipt: { payload: sent, signature: { alg: "ed25519", key_id: key.keyId, value: await signer.sign(sent), ...signature } } });
}

/** Calls a handler with a MemoryStore, a session and a clock, and returns status, headers and parsed JSON. */
export function harness(defaults: { store?: MemoryStore; session?: Session; now?: number } = {}) {
  const store = defaults.store ?? new MemoryStore();
  const call = async (handler: ActionHandler, body: Uint8Array, overrides: Partial<Omit<ActionContext, "store">> = {}) => {
    const ctx: ActionContext = { store, session: defaults.session ?? session(), now: defaults.now ?? T0, ...overrides };
    const response = await handler(ctx, body);
    return { status: response.status, headers: response.headers, body: await response.json() as Record<string, unknown> };
  };
  return { store, call };
}
