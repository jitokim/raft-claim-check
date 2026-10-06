import type { ActionContext, ActionHandler, Session } from "../src/context";
import { keyId } from "../src/crypto";
import { canonicalize } from "../src/jcs";
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
    sign: async (payload) => `ed25519:${b64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(canonicalize(payload)))))}`,
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
