// Cross-checks the Worker against the shared vectors in spec/vectors/, which the CLI generates (cli/cmd/genvectors).
// Every value is re-derived with the Worker's own exported functions; the test only reads files and compares.
import { readdirSync, readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { keyId, parsePublicKey, parseSignature, receiptId, sha256, verifyEd25519 } from "../src/crypto";
import { canonicalBytes, canonicalize, JsonError, parseJson, type JsonValue, type NumberIssue } from "../src/jcs";
import { registerKey } from "../src/keys";
import { validatePayload } from "../src/receipt-schema";
import { encode, harness, session } from "./helpers";

const VECTORS = new URL("../spec/vectors/", import.meta.url);
const FILES = ["jcs-cases.json", "key.json", "receipt-attest.json", "receipt-run.json", "registration.json"];

// The vector files hold integers only, so the Worker's strict parser reads them.
const load = <T>(name: string) => parseJson(readFileSync(new URL(name, VECTORS), "utf8")) as T;
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

interface KeyVector { comment: string; seed_hex: string; public_key: string; key_id: string }
interface Envelope { payload: { [key: string]: JsonValue }; signature: { alg: string; key_id: string; value: string } }
interface SignedVector { payload: { [key: string]: JsonValue }; jcs: string; sha256: string; envelope: Envelope; receipt_id?: string }
interface JcsCase { input: string; output: string; error?: string }

const key = load<KeyVector>("key.json");
const signed: [string, SignedVector][] = ["receipt-run.json", "receipt-attest.json", "registration.json"].map((name) => [name, load<SignedVector>(name)]);
const receipts = signed.filter(([name]) => name.startsWith("receipt-"));
const cases = load<JcsCase[]>("jcs-cases.json");

describe("spec/vectors", () => {
  it("holds exactly the known vector files", () => {
    expect(readdirSync(VECTORS).sort()).toEqual(FILES);
  });
});

describe("key.json", () => {
  it("key_id derives from public_key", async () => {
    expect(await keyId(parsePublicKey(key.public_key))).toBe(key.key_id);
  });
});

describe.each(signed)("%s", (_name, vector) => {
  it("JCS of payload equals jcs byte for byte", () => {
    expect(canonicalize(vector.payload)).toBe(vector.jcs);
    expect(Buffer.compare(Buffer.from(canonicalBytes(vector.payload)), Buffer.from(vector.jcs, "utf8"))).toBe(0);
  });

  it("SHA-256 of the JCS bytes equals sha256", async () => {
    expect(hex(await sha256(canonicalBytes(vector.payload)))).toBe(vector.sha256);
  });

  it("envelope carries the payload and names key.json's key", async () => {
    expect(vector.envelope.payload).toEqual(vector.payload);
    expect(vector.envelope.signature.alg).toBe("ed25519");
    expect(vector.envelope.signature.key_id).toBe(await keyId(parsePublicKey(key.public_key)));
    expect(vector.payload.key_id).toBe(key.key_id);
  });

  it("signature verifies under key.json's public key, and not over a payload with one byte flipped", async () => {
    const publicKey = parsePublicKey(key.public_key);
    const signature = parseSignature(vector.envelope.signature.value);
    const message = canonicalBytes(vector.envelope.payload);
    expect(await verifyEd25519(publicKey, signature, message)).toBe(true);
    const tampered = message.slice();
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    expect(await verifyEd25519(publicKey, signature, tampered)).toBe(false);
  });
});

describe.each(receipts)("%s receipt_id", (_name, vector) => {
  it("derives from the payload", async () => {
    expect(vector.receipt_id).toMatch(/^rcpt_/);
    expect(await receiptId(vector.payload)).toBe(vector.receipt_id);
  });
});

describe("jcs-cases.json", () => {
  // The Worker's real JCS is submit_receipt's: step 4 parses recording number-domain issues instead of throwing, and
  // step 9 signs over canonicalBytes(payload, "finite"). Number issues fail only at step 10, as schema_invalid.
  const step9 = (input: string, issues: NumberIssue[]) => canonicalBytes(parseJson(input, issues), "finite");
  const strictCode = (input: string) => {
    try { canonicalize(parseJson(input)); } catch (cause) { return cause instanceof JsonError ? cause.code : String(cause); }
    return undefined;
  };

  it.each(cases.map((entry, index) => [index, entry] as const))("case %i", (_index, entry) => {
    // No vector carries error today. One would be a rejection on the same path: a throw at step 4 or 9, else a number issue.
    if (entry.error !== undefined) {
      const issues: NumberIssue[] = [];
      let code: string | undefined;
      try { step9(entry.input, issues); } catch (cause) { code = cause instanceof JsonError ? cause.code : String(cause); }
      expect(code ?? issues[0]?.code).toBe(entry.error);
      return;
    }
    const issues: NumberIssue[] = [];
    expect(Buffer.compare(Buffer.from(step9(entry.input, issues)), Buffer.from(entry.output, "utf8"))).toBe(0);

    // The strict integers-only path (register_key, receipt_id) either agrees or refuses only for a recorded number issue.
    const code = strictCode(entry.input);
    if (code === undefined) expect(canonicalize(parseJson(entry.input))).toBe(entry.output);
    else expect(issues.map((issue) => issue.code)).toContain(code);
  });

  it("case 10: -0 canonicalizes to 0 at step 9, and the strict path's negative_zero is step 10's schema_invalid", () => {
    const entry = cases[10];
    expect(entry.input).toBe("[9007199254740992,-9007199254740992,0,-0,1,-1]");
    const issues: NumberIssue[] = [];
    expect(new TextDecoder().decode(step9(entry.input, issues))).toBe(entry.output);
    expect(issues).toEqual([{ path: "[3]", code: "negative_zero" }]);
    expect(strictCode(entry.input)).toBe("negative_zero");

    // Inside a submit_receipt body the same issue names the payload field, and validatePayload refuses it.
    const bodyIssues: NumberIssue[] = [];
    const body = parseJson(`{"receipt":{"payload":{"n":${entry.input}}}}`, bodyIssues) as { receipt: { payload: { [key: string]: JsonValue } } };
    expect(bodyIssues).toEqual([{ path: "receipt.payload.n[3]", code: "negative_zero" }]);
    expect(validatePayload(body.receipt.payload, bodyIssues)).toBe("payload.n[3] must be an integer within +/-2^53, without fraction, exponent or -0.");
  });
});

describe("registration.json through register_key", () => {
  it("proves possession and stores the vector's key for its server and principal", async () => {
    const { envelope } = signed.find(([name]) => name === "registration.json")![1];
    const { payload } = envelope;
    const { store, call } = harness({
      session: session({ server_id: payload.server_id as string, principal_id: payload.principal_id as string, server_slug: "test" }),
      now: Date.parse(payload.issued_at as string),
    });
    const result = await call(registerKey, encode({ registration: envelope }));
    expect(result.status).toBe(201);
    expect(result.body).toMatchObject({ key_id: key.key_id, public_key: key.public_key, status: "active" });
    expect(store.keys).toHaveLength(1);
    expect(store.keys[0]).toMatchObject({
      key_id: key.key_id, public_key: key.public_key, server_id: payload.server_id, principal_id: payload.principal_id,
    });
  });
});
