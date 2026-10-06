// Key actions (docs/design-v2.md, ## Key lifecycle and ## Actions).
import type { ActionContext, ActionHandler, Session } from "./context";
import { keyId, parsePublicKey, parseSignature, verifyEd25519 } from "./crypto";
import { error, hasOnlyKeys, invalidRequest, isJsonObject, json, parseJsonObject, type JsonObject } from "./http";
import { canonicalBytes } from "./jcs";
import { reserve } from "./ratelimit";
import type { KeyRow } from "./store";
import { parseUtcMillis, toUtcMillis } from "./time";

export const REGISTRATION_SCHEMA = "claim-check.key-registration.v2";
export const MAX_ACTIVE_KEYS = 5;
const REGISTRATION_WINDOW_MS = 10 * 60_000;
const MAX_STRING_BYTES = 1024;
const KEY_ID = /^ck_[a-z2-7]{26}$/;

const REQUIRED_FIELDS = ["public_key", "key_id", "server_id", "principal_id", "nonce", "issued_at"] as const;
const OPTIONAL_FIELDS = ["label", "cli_version"] as const;
const STATEMENT_FIELDS: readonly string[] = ["schema", ...REQUIRED_FIELDS, ...OPTIONAL_FIELDS];

interface Statement {
  public_key: string;
  key_id: string;
  server_id: string;
  principal_id: string;
  label: string | null;
  publicKey: Uint8Array;
  issuedAt: number;
}

const utf8Length = (text: string) => new TextEncoder().encode(text).byteLength;

/** Field-level validation of a registration statement: a Statement, or the hint for 400 invalid_request. */
function validateStatement(payload: JsonObject): Statement | string {
  if (payload.schema !== REGISTRATION_SCHEMA) return `payload.schema must be ${REGISTRATION_SCHEMA}.`;
  const unknown = Object.keys(payload).find((key) => !STATEMENT_FIELDS.includes(key));
  if (unknown !== undefined) return `payload has an unknown field ${JSON.stringify(unknown).slice(0, 64)}.`;
  for (const field of [...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]) {
    const value = payload[field];
    const required = (REQUIRED_FIELDS as readonly string[]).includes(field);
    if (value === undefined) {
      if (required) return `payload.${field} is required.`;
      continue;
    }
    if (typeof value !== "string") return `payload.${field} must be a string.`;
    if (required && value === "") return `payload.${field} must not be empty.`;
    if (utf8Length(value) > MAX_STRING_BYTES) return `payload.${field} must be at most 1 KB.`;
  }
  const fields = payload as Record<(typeof REQUIRED_FIELDS)[number], string> & { label?: string };
  let publicKey: Uint8Array;
  try { publicKey = parsePublicKey(fields.public_key); } catch { return "payload.public_key must be ed25519: followed by unpadded base64url of 32 bytes."; }
  if (!KEY_ID.test(fields.key_id)) return "payload.key_id must be ck_ followed by 26 lowercase base32 characters.";
  const issuedAt = parseUtcMillis(fields.issued_at);
  if (issuedAt === null) return "payload.issued_at must be an RFC 3339 UTC time with milliseconds.";
  return {
    public_key: fields.public_key, key_id: fields.key_id, server_id: fields.server_id, principal_id: fields.principal_id,
    label: fields.label ?? null, publicKey, issuedAt,
  };
}

/** The proof of possession: alg, key_id agreement, key_id derived from public_key, and the signature over JCS(payload). */
async function provesPossession(statement: Statement, payload: JsonObject, signature: JsonObject): Promise<boolean> {
  if (signature.alg !== "ed25519" || signature.key_id !== statement.key_id) return false;
  if (await keyId(statement.publicKey) !== statement.key_id) return false;
  let signatureBytes: Uint8Array;
  try { signatureBytes = parseSignature(signature.value as string); } catch { return false; }
  return verifyEd25519(statement.publicKey, signatureBytes, canonicalBytes(payload));
}

function registrationRecord(session: Session, row: KeyRow) {
  return {
    key_id: row.key_id, public_key: row.public_key, label: row.label, status: "active", registered_at: row.registered_at,
    server: { id: session.server_id, slug: session.server_slug }, principal: { id: row.principal_id, type: row.principal_type },
  };
}

/** The answer for a key that already has a row: revoked, bound elsewhere, or idempotently registered. */
function existingKey(session: Session, row: KeyRow): Response {
  if (row.revoked_at !== null) return error(409, "key_revoked", "This key was revoked and can never be registered again; generate a new key.");
  if (row.server_id !== session.server_id || row.principal_id !== session.principal_id) {
    return error(409, "key_bound_elsewhere", "This key is already bound to another server or principal.");
  }
  return json(registrationRecord(session, row), 200);
}

export const registerKey: ActionHandler = async (ctx: ActionContext, body) => {
  const { session, store, now } = ctx;
  const request = parseJsonObject(body);
  const registration = request?.registration;
  if (!request || !hasOnlyKeys(request, ["registration"]) || !isJsonObject(registration) || !hasOnlyKeys(registration, ["payload", "signature"])
    || !isJsonObject(registration.payload) || !isJsonObject(registration.signature)) {
    return invalidRequest("The body must be a JSON object {registration: {payload, signature}} without duplicate keys.");
  }
  const { payload, signature } = registration;
  if (!hasOnlyKeys(signature, ["alg", "key_id", "value"]) || typeof signature.alg !== "string" || typeof signature.key_id !== "string" || typeof signature.value !== "string") {
    return invalidRequest("registration.signature must be {alg, key_id, value} with string values.");
  }

  // The reservation comes before any signature work, so a flood of bad signatures is not free.
  const limited = await reserve(store, "register", session, now);
  if (limited) return limited;

  const statement = validateStatement(payload);
  if (typeof statement === "string") return invalidRequest(statement);
  if (!(await provesPossession(statement, payload, signature))) {
    return error(400, "bad_signature", "The signature does not verify under payload.public_key, or key_id does not match the public key.");
  }
  if (statement.server_id !== session.server_id || statement.principal_id !== session.principal_id) {
    return error(400, "registration_mismatch", "payload.server_id and payload.principal_id must be this session's; read them with get_session.");
  }
  if (Math.abs(statement.issuedAt - now) > REGISTRATION_WINDOW_MS) {
    return error(400, "registration_expired", "payload.issued_at must be within 10 minutes of the app's clock; sign a fresh statement.");
  }

  const existing = await store.getKey(statement.key_id);
  if (existing) return existingKey(session, existing);
  const row: KeyRow = {
    key_id: statement.key_id, public_key: statement.public_key, server_id: session.server_id, principal_id: session.principal_id,
    principal_type: session.principal_type, label: statement.label, registered_at: toUtcMillis(now),
    revoked_at: null, revoked_reason: null, compromised_since: null,
  };
  if (await store.insertKey(row, MAX_ACTIVE_KEYS)) return json(registrationRecord(session, row), 201);
  // Not inserted: either a concurrent request stored this key first, or the active-key cap blocked it.
  const raced = await store.getKey(statement.key_id);
  if (raced) return existingKey(session, raced);
  return error(409, "too_many_keys", `You already have ${MAX_ACTIVE_KEYS} active keys on this server; revoke one with revoke_key first.`);
};
