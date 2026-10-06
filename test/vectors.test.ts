// Cross-checks the Worker against the shared vectors in spec/vectors/, which the CLI generates (cli/cmd/genvectors).
// Every value is re-derived with the Worker's own exported functions; the test only reads files and compares.
import { readdirSync, readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { keyId, parsePublicKey, parseSignature, receiptId, sha256, verifyEd25519 } from "../src/crypto";
import { canonicalBytes, canonicalize, JsonError, parseJson, type JsonValue, type NumberIssue } from "../src/jcs";
import { registerKey } from "../src/keys";
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
  // Generic RFC 8785 cases are not v2 payloads, so they go through the Worker's RFC 8785 path: the parser recording
  // number-domain issues instead of throwing, and the "finite" canonicalizer that step 9 of ## Verification signs over.
  it.each(cases.map((entry, index) => [index, entry] as const))("case %i", (_index, entry) => {
    if (entry.error !== undefined) {
      let code: string | undefined;
      try { canonicalize(parseJson(entry.input)); } catch (cause) { code = cause instanceof JsonError ? cause.code : String(cause); }
      expect(code).toBe(entry.error);
      return;
    }
    const issues: NumberIssue[] = [];
    expect(canonicalize(parseJson(entry.input, issues), "finite")).toBe(entry.output);

    // The strict v2 payload parser (## Receipt schema: integers within +/-2^53 only) either agrees or refuses only
    // for the number domain, never for anything else.
    let strict: string | undefined, code: string | undefined;
    try { strict = canonicalize(parseJson(entry.input)); } catch (cause) { code = cause instanceof JsonError ? cause.code : String(cause); }
    if (code === undefined) expect(strict).toBe(entry.output);
    else expect(issues.map((issue) => issue.code)).toContain(code);
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
