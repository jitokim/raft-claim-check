// Receipt actions (docs/design-v2.md, ## Verification, ## Receipt visibility and ## What a receipt proves and does not prove).
import type { ActionHandler, Session } from "./context";
import { parsePublicKey, parseSignature, receiptId, verifyEd25519 } from "./crypto";
import { error, hasOnlyKeys, invalidRequest, isJsonObject, json, parseJsonObject, type JsonObject } from "./http";
import { canonicalBytes, canonicalize, JsonError, parseJson, type NumberIssue } from "./jcs";
import { reserve } from "./ratelimit";
import { validatePayload, type ReceiptPayload } from "./receipt-schema";
import type { KeyRow, StoredReceipt } from "./store";
import { toUtcMillis } from "./time";

export const RECEIPT_SCHEMA = "claim-check.receipt.v2";
const MINUTE = 60_000;
const DAY = 86_400_000;
const RETENTION_MS = 90 * DAY;
const MAX_FUTURE_SKEW_MS = 5 * MINUTE;
const MAX_AGE_MS = 7 * DAY;
const LATE_AFTER_MS = 10 * MINUTE;

interface LedgerKey { key_id: string; public_key: string; status: "active" | "revoked"; revoked_at: string | null; compromised_window: boolean }

/** The app's own statements about a receipt; not signed by the CLI. Field order follows the doc's example stored receipt. */
interface Ledger {
  received_at: string;
  expires_at: string;
  server: { id: string; slug: string };
  submitted_by: { principal_id: string; principal_type: string };
  key: LedgerKey;
  submitted_late: boolean;
  acceptance_surface: string;
  verified: string[];
  asserted: string[];
  proved: string[];
  not_proved: string[];
}

const RUN_NOT_PROVED = [
  "That the CLI was unmodified, or that the command ran at all; everything in payload is asserted by the key holder",
  "That the command checks what the claim is about",
  "That git.head is pushed, reviewed, merged or deployed, or that a dirty: true tree contained anything in particular",
  "That the environment, inputs, network or time matched any other run, or that the result is reproducible",
  "That this was the only attempt; the CLI submits every run, but a lying owner can withhold the red ones",
  "Anything after finished_at",
];

const ATTEST_NOT_PROVED = [
  "That the file is the output of any particular command or commit",
  "That it is the file that was shipped, uploaded or deployed",
  "That its contents are correct",
];

/** The ledger stored with a new receipt. The key is active at received_at, so it is never in a compromised window yet. */
function buildLedger(payload: ReceiptPayload, session: Session, key: KeyRow, now: number, signedAt: number): Ledger {
  const k = key.key_id, server = session.server_id, principal = session.principal_id;
  const receivedAt = toUtcMillis(now);
  const verified = [
    `signature valid over JCS(payload) for key ${k}`,
    `key registered with proof of possession, bound to server ${server} and principal ${principal}, active at received_at`,
    `submitted by principal ${principal} through its Claim Check session`,
    "received_at from the app's clock",
    "schema and consistency checks passed",
  ];
  const signedThis = `The holder of key ${k}, bound to principal ${principal} on server ${server}, signed this exact record, and it reached the ledger at ${receivedAt} while ${k} was active`;
  let acceptanceSurface: string, proved: string[], notProved: string[];
  if (payload.run) {
    const { argv, exit } = payload.run;
    const git = payload.git;
    const checkout = git ? "in the recorded git checkout" : "outside any git repository";
    const state = git ? `with HEAD ${git.head ?? "none (no commit yet)"} and dirty flag ${git.dirty}` : "outside any git repository";
    const outcome = exit.code !== null ? `exited with code ${exit.code}` : `was terminated by signal ${exit.signal}`;
    acceptanceSurface = `Exit status and output of argv [${argv.join(" ")}] ${checkout}, on the machine holding key ${k}`;
    proved = [signedThis, `Asserted by the key holder: argv ran ${state}, ${outcome}, and produced output whose full bytes hash to the recorded digests`];
    notProved = RUN_NOT_PROVED;
  } else {
    const attest = payload.attest!;
    acceptanceSurface = `The bytes of the file ${attest.path} on the machine holding key ${k}`;
    proved = [signedThis, `Asserted by the key holder: at ${attest.observed_at}, the file at ${attest.path} had SHA-256 ${attest.sha256} and size ${attest.bytes}`];
    notProved = ATTEST_NOT_PROVED;
  }
  return {
    received_at: receivedAt,
    expires_at: toUtcMillis(now + RETENTION_MS),
    server: { id: server, slug: session.server_slug },
    submitted_by: { principal_id: principal, principal_type: session.principal_type },
    key: { key_id: k, public_key: key.public_key, status: "active", revoked_at: null, compromised_window: false },
    submitted_late: signedAt < now - LATE_AFTER_MS,
    acceptance_surface: acceptanceSurface,
    verified,
    asserted: [`${payload.kind}.*`, "git.*", "cli.*", "signed_at"],
    proved,
    not_proved: notProved,
  };
}

/** {receipt_id, envelope, ledger} with ledger.key showing the key's current status; the rest is exactly as stored. */
export function storedReceiptBody(stored: StoredReceipt) {
  const ledger = JSON.parse(stored.ledger_json) as Ledger;
  const since = stored.key_compromised_since;
  ledger.key = {
    ...ledger.key,
    status: stored.key_revoked_at === null ? "active" : "revoked",
    revoked_at: stored.key_revoked_at,
    compromised_window: since !== null && Date.parse(stored.received_at) >= Date.parse(since),
  };
  return { receipt_id: stored.id, envelope: JSON.parse(stored.envelope_json) as JsonObject, ledger };
}

const receiptNotFound = () => error(404, "receipt_not_found", "No accessible, unexpired receipt has that ID.");

/**
 * get_receipt: one query scoped by the session's server and to unexpired rows. Unknown, malformed, expired and
 * other-server IDs all get the identical 404. Members other than receipt_id are ignored, as list_keys ignores its body.
 */
export const getReceipt: ActionHandler = async ({ store, session, now }, body) => {
  const request = parseJsonObject(body);
  if (!request) return invalidRequest("The request body must be a JSON object {receipt_id} without duplicate keys.");
  const limited = await reserve(store, "read", session, now);
  if (limited) return limited;
  const id = request.receipt_id;
  // A non-string ID cannot match a row; it gets the same 404 without a query that could tell it apart.
  const stored = typeof id === "string" ? await store.readReceipt(id, session.server_id, toUtcMillis(now)) : null;
  return stored ? json(storedReceiptBody(stored)) : receiptNotFound();
};

/** Step 4's parse: duplicate keys and malformed JSON fail here; number-domain issues are only recorded, for step 10. */
function parseRequest(body: Uint8Array, numberIssues: NumberIssue[]): JsonObject | null {
  try {
    const value = parseJson(body, numberIssues);
    return isJsonObject(value) ? value : null;
  } catch (cause) {
    if (cause instanceof JsonError) return null;
    throw cause;
  }
}

/** Step 9: alg, strict signature encoding, and ed25519 over UTF-8 JCS(payload) with the stored public key. */
async function signatureVerifies(key: KeyRow, payload: JsonObject, signature: JsonObject): Promise<boolean> {
  if (signature.alg !== "ed25519" || typeof signature.value !== "string") return false;
  let signatureBytes: Uint8Array, message: Uint8Array;
  try {
    signatureBytes = parseSignature(signature.value);
    // Floats are canonicalized as RFC 8785 does, so a signed float reaches step 10 and fails there as schema_invalid.
    // A number JCS cannot express at all (1e400) leaves nothing that could have been signed: bad_signature.
    message = canonicalBytes(payload, "finite");
  } catch {
    return false;
  }
  return verifyEd25519(parsePublicKey(key.public_key), signatureBytes, message);
}

/**
 * submit_receipt, steps 4 to 13 of ## Verification; the router has run steps 1 (size, 413) to 3 (session, scopes,
 * blocked_servers). Each step returns at its first failure.
 */
export const submitReceipt: ActionHandler = async ({ store, session, now }, body) => {
  // 4. Shape. The envelope and its signature carry nothing beyond the documented members (stricter; stored verbatim).
  const numberIssues: NumberIssue[] = [];
  const request = parseRequest(body, numberIssues);
  const receipt = request?.receipt;
  if (!request || !hasOnlyKeys(request, ["receipt"]) || !isJsonObject(receipt) || !hasOnlyKeys(receipt, ["payload", "signature"])
    || !isJsonObject(receipt.payload) || !isJsonObject(receipt.signature) || !hasOnlyKeys(receipt.signature, ["alg", "key_id", "value"])) {
    return invalidRequest("The body must be a JSON object {receipt: {payload, signature}} with object payload and signature and no duplicate keys.");
  }
  const { payload, signature } = receipt;

  // 5. Rate-limit reservation, before any CPU-costly step. A failure after this point is not refunded.
  const limited = await reserve(store, "submit", session, now);
  if (limited) return limited;

  // 6. Schema version.
  if (payload.schema !== RECEIPT_SCHEMA || (payload.kind !== "run" && payload.kind !== "attest")) {
    return error(400, "schema_unsupported", `payload.schema must be ${RECEIPT_SCHEMA} and payload.kind must be run or attest.`);
  }

  // 7. Binding fields. Missing or non-string values never match.
  const boundTo = payload.bound_to;
  if (!isJsonObject(boundTo) || boundTo.server_id !== session.server_id || boundTo.principal_id !== session.principal_id
    || typeof payload.key_id !== "string" || signature.key_id !== payload.key_id) {
    return error(400, "binding_mismatch", "payload.bound_to must be this session's server_id and principal_id, and signature.key_id must equal payload.key_id.");
  }

  // 8. Key lookup and binding: unknown and bound-elsewhere keys get the identical 403.
  const key = await store.getBoundKey(payload.key_id, session.server_id, session.principal_id);
  if (!key) return error(403, "key_not_registered", "This key is not registered to you on this server; run claim-check key register.");
  if (key.revoked_at !== null) return error(403, "key_revoked", "This key was revoked and can sign no new receipts.");

  // 9. Signature.
  if (!(await signatureVerifies(key, payload, signature))) {
    return error(400, "bad_signature", "The signature does not verify over JCS(payload) with the registered key.");
  }

  // 10. Schema checks.
  const valid = validatePayload(payload, numberIssues);
  if (typeof valid === "string") return error(400, "schema_invalid", valid);

  // 11. Timestamp skew window, against the app's clock at receipt.
  if (valid.signedAt > now + MAX_FUTURE_SKEW_MS) return error(400, "clock_skew", "payload.signed_at is more than 5 minutes in the future; check this machine's clock.");
  if (valid.signedAt < now - MAX_AGE_MS) return error(400, "receipt_too_old", "payload.signed_at is more than 7 days ago; the receipt can no longer be accepted.");

  // 12. Replay and duplicates. The payload is integer-only from here on, so plain JCS applies.
  const id = await receiptId(payload);
  const envelope = { payload, signature };
  const ledger = buildLedger(valid.payload, session, key, now, valid.signedAt);
  const inserted = await store.insertReceipt({
    id, server_id: session.server_id, principal_id: session.principal_id, principal_type: session.principal_type, key_id: key.key_id,
    kind: valid.payload.kind, signed_at: valid.payload.signed_at, received_at: ledger.received_at, expires_at: ledger.expires_at,
    envelope_json: canonicalize(envelope), ledger_json: JSON.stringify(ledger),
  });
  if (!inserted) {
    // The ID derives from a payload that names this server and principal, so the stored row is on this server.
    const stored = await store.readReceipt(id, session.server_id, ledger.received_at);
    if (!stored) throw new Error("A conflicting receipt row could not be read back.");
    return json({ ...storedReceiptBody(stored), duplicate: true }, 200);
  }

  // 13. Stored: the envelope as JCS and the ledger.
  return json({ receipt_id: id, envelope, ledger, duplicate: false }, 201);
};
