import { describe, it, expect } from "vitest";
import {
  base32Encode, base64urlDecode, base64urlEncode, EncodingError, keyId, parsePublicKey, parseSignature, receiptId, sha256, verifyEd25519,
} from "../src/crypto";
import { canonicalize, type JsonValue } from "../src/jcs";

// Test-side encoders use Node's Buffer, independent of the module under test.
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const fromHex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const errorCode = (fn: () => unknown): string | undefined => {
  try { fn(); } catch (error) { return error instanceof EncodingError ? error.code : `not an EncodingError: ${String(error)}`; }
  return undefined;
};

// L = 2^252 + 27742317777372353535851937790883648493 = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const L_LE_HEX = "edd3f55c1a631258d69cf7a2def9de14" + "00".repeat(15) + "10";
const littleEndian32 = (value: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((value >> BigInt(8 * i)) & 0xffn));

async function keypair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey) as ArrayBuffer);
  const sign = async (message: Uint8Array) => new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, message));
  return { raw, sign };
}

describe("ed25519", () => {
  const message = new TextEncoder().encode('{"kind":"run","schema":"claim-check.receipt.v2"}');

  it("verifies a good signature and rejects a flipped signature or message byte", async () => {
    const { raw, sign } = await keypair();
    const signature = await sign(message);
    const publicKey = parsePublicKey(`ed25519:${b64url(raw)}`);
    const parsed = parseSignature(`ed25519:${b64url(signature)}`);
    expect(hex(publicKey)).toBe(hex(raw));
    expect(hex(parsed)).toBe(hex(signature));
    expect(await verifyEd25519(publicKey, parsed, message)).toBe(true);

    for (const index of [0, 31, 32, 63]) {
      const badSignature = parsed.slice();
      badSignature[index] ^= 0x01;
      expect(await verifyEd25519(publicKey, badSignature, message), `signature byte ${index}`).toBe(false);
    }
    for (const index of [0, message.length - 1]) {
      const badMessage = message.slice();
      badMessage[index] ^= 0x01;
      expect(await verifyEd25519(publicKey, parsed, badMessage), `message byte ${index}`).toBe(false);
    }
    const other = await keypair();
    expect(await verifyEd25519(other.raw, parsed, message)).toBe(false);
    expect(await verifyEd25519(publicKey.subarray(0, 31), parsed, message)).toBe(false);
    expect(await verifyEd25519(publicKey, parsed.subarray(0, 63), message)).toBe(false);
  });

  it("rejects every non-canonical signature encoding", async () => {
    const { sign } = await keypair();
    const signature = await sign(message);
    const body = b64url(signature);
    expect(body).toHaveLength(86);
    const bumpLast = (text: string) => text.slice(0, -1) + B64URL[B64URL.indexOf(text.at(-1)!) + 1];
    const withS = (s: Uint8Array) => {
      const bytes = signature.slice();
      bytes.set(s, 32);
      return `ed25519:${b64url(bytes)}`;
    };
    expect(hex(littleEndian32(L))).toBe(L_LE_HEX);

    const cases: [string, string, string][] = [
      ["wrong prefix: missing colon", `ed25519${body}`, "bad_prefix"],
      ["wrong prefix: capitalised", `Ed25519:${body}`, "bad_prefix"],
      ["wrong prefix: other algorithm", `ecdsa:${body}`, "bad_prefix"],
      ["wrong prefix: none", body, "bad_prefix"],
      ["length 85", `ed25519:${body.slice(0, 85)}`, "bad_length"],
      ["length 87", `ed25519:${body}A`, "bad_length"],
      ["padding appended", `ed25519:${body}==`, "bad_length"],
      ["padding inside 86 characters", `ed25519:${body.slice(0, 84)}==`, "bad_base64url"],
      ["standard base64 '+'", `ed25519:+${body.slice(1)}`, "bad_base64url"],
      ["standard base64 '/'", `ed25519:/${body.slice(1)}`, "bad_base64url"],
      ["character '.'", `ed25519:${body.slice(0, 40)}.${body.slice(41)}`, "bad_base64url"],
      ["whitespace", `ed25519:${body.slice(0, 85)} `, "bad_base64url"],
      ["non-zero trailing bits", `ed25519:${bumpLast(body)}`, "non_canonical"],
      ["S = L", withS(fromHex(L_LE_HEX)), "non_canonical"],
      ["S = L + 1", withS(littleEndian32(L + 1n)), "non_canonical"],
      ["S = 2^256 - 1", withS(new Uint8Array(32).fill(0xff)), "non_canonical"],
    ];
    for (const [name, text, code] of cases) expect(errorCode(() => parseSignature(text)), name).toBe(code);
    // The last character of 64 bytes carries 4 trailing bits, so the canonical form ends in A, Q, g or w.
    expect("AQgw").toContain(body.at(-1));
    // S = L - 1 is the largest canonical scalar.
    expect(parseSignature(withS(littleEndian32(L - 1n)))).toHaveLength(64);
  });

  it("parses public keys strictly", () => {
    const raw = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const body = b64url(raw);
    expect(body).toHaveLength(43);
    expect(hex(parsePublicKey(`ed25519:${body}`))).toBe(hex(raw));
    expect(errorCode(() => parsePublicKey(`ed25519${body}`))).toBe("bad_prefix");
    expect(errorCode(() => parsePublicKey(`ed25519:${body}=`))).toBe("bad_length");
    expect(errorCode(() => parsePublicKey(`ed25519:${body.slice(0, 42)}`))).toBe("bad_length");
    // 43 characters carry 2 trailing bits, so a last character such as "b" (27 = 011011) is never canonical.
    expect(errorCode(() => parsePublicKey(`ed25519:${body.slice(0, 42)}b`))).toBe("non_canonical");
  });
});

describe("encodings", () => {
  it("base32 matches the RFC 4648 vectors, lowercase and unpadded", () => {
    const vectors: [string, string][] = [["", ""], ["f", "my"], ["fo", "mzxq"], ["foo", "mzxw6"], ["foob", "mzxw6yq"], ["fooba", "mzxw6ytb"], ["foobar", "mzxw6ytboi"]];
    for (const [input, output] of vectors) expect(base32Encode(new TextEncoder().encode(input))).toBe(output);
  });

  it("base64url round-trips and rejects non-canonical input", () => {
    for (let length = 0; length < 70; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length) & 0xff);
      const encoded = b64url(bytes);
      expect(base64urlEncode(bytes)).toBe(encoded);
      expect(hex(base64urlDecode(encoded))).toBe(hex(bytes));
    }
    expect(errorCode(() => base64urlDecode("Zm9v="))).toBe("bad_base64url");
    expect(errorCode(() => base64urlDecode("Zg=="))).toBe("bad_base64url");
    expect(errorCode(() => base64urlDecode("Z"))).toBe("bad_base64url");
    expect(errorCode(() => base64urlDecode("Zh"))).toBe("non_canonical");
    expect(hex(base64urlDecode("Zg"))).toBe("66");
  });
});

describe("ID derivation", () => {
  it("derives the golden keyId of 32 zero bytes", async () => {
    const zeros = new Uint8Array(32);
    expect(hex(await sha256(zeros))).toBe("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    // First 16 bytes: 66 68 7a ad f8 | 62 bd 77 6c 8f | c1 8b 8e 9f 8e | 20
    // 66687aadf8 = 01100 11001 10100 00111 10101 01011 01111 11000 = 12 25 20 7 21 11 15 24 = m z u h v l p y
    // 62bd776c8f = 01100 01010 11110 10111 01110 11011 00100 01111 = 12 10 30 23 14 27 4 15 = m k 6 x o 3 e p
    // c18b8e9f8e = 11000 00110 00101 11000 11101 00111 11100 01110 = 24 6 5 24 29 7 28 14 = y g f y 5 h 4 o
    // 20         = 00100 000(00)                                   = 4 0                  = e a
    expect(await keyId(zeros)).toBe("ck_mzuhvlpymk6xo3epygfy5h4oea");
    await expect(keyId(new Uint8Array(31))).rejects.toBeInstanceOf(EncodingError);
  });

  it("derives the golden receiptId of {}", async () => {
    expect(canonicalize({})).toBe("{}");
    expect(hex(await sha256(new TextEncoder().encode("{}")))).toBe("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    // First 16 bytes: 44 13 6f a3 55 | b3 67 8a 11 46 | ad 16 f7 e8 64 | 9e
    // 44136fa355 = 01000 10000 01001 10110 11111 01000 11010 10101 = 8 16 9 22 31 8 26 21 = i q j w 7 i 2 v
    // b3678a1146 = 10110 01101 10011 11000 10100 00100 01010 00110 = 22 13 19 24 20 4 10 6 = w n t y u e k g
    // ad16f7e864 = 10101 10100 01011 01111 01111 11010 00011 00100 = 21 20 11 15 15 26 3 4 = v u l p p 2 d e
    // 9e         = 10011 110(00)                                   = 19 24                = t y
    expect(await receiptId({})).toBe("rcpt_iqjw7i2vwntyuekgvulpp2dety");
  });

  it("derives a run receipt ID from the JCS of a realistic payload, independent of key order", async () => {
    const payload: JsonValue = {
      schema: "claim-check.receipt.v2",
      kind: "run",
      nonce: "AAECAwQFBgcICQoLDA0ODw",
      key_id: "ck_mzuhvlpymk6xo3epygfy5h4oea",
      bound_to: { server_id: "srv_1", principal_id: "agent_1" },
      cli: { name: "claim-check", version: "2.0.0", os: "darwin", arch: "arm64" },
      signed_at: "2026-10-06T09:00:03.120Z",
      git: { remote_url: "https://github.com/example/widgets.git", head: "0123456789abcdef0123456789abcdef01234567", branch: "main", dirty: false },
      run: {
        argv: ["go", "test", "./...", "-token=[REDACTED:sensitive_flag]"],
        argv_redactions: 1,
        cwd_rel: ".",
        started_at: "2026-10-06T09:00:00.020Z",
        finished_at: "2026-10-06T09:00:03.050Z",
        duration_ms: 3030,
        exit: { code: 0, signal: null },
        stdout: {
          sha256: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          bytes: 18234,
          tail: "ok  \texample.com/widgets/api\t1.204s\nok  \texample.com/widgets/store\t0.811s\n",
          tail_truncated: true,
          tail_redactions: 0,
        },
        stderr: {
          sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          bytes: 0,
          tail: "",
          tail_truncated: false,
          tail_redactions: 0,
        },
      },
    };
    const expected = String.raw`{"bound_to":{"principal_id":"agent_1","server_id":"srv_1"},`
      + String.raw`"cli":{"arch":"arm64","name":"claim-check","os":"darwin","version":"2.0.0"},`
      + String.raw`"git":{"branch":"main","dirty":false,"head":"0123456789abcdef0123456789abcdef01234567","remote_url":"https://github.com/example/widgets.git"},`
      + String.raw`"key_id":"ck_mzuhvlpymk6xo3epygfy5h4oea","kind":"run","nonce":"AAECAwQFBgcICQoLDA0ODw",`
      + String.raw`"run":{"argv":["go","test","./...","-token=[REDACTED:sensitive_flag]"],"argv_redactions":1,"cwd_rel":".","duration_ms":3030,`
      + String.raw`"exit":{"code":0,"signal":null},"finished_at":"2026-10-06T09:00:03.050Z","started_at":"2026-10-06T09:00:00.020Z",`
      + String.raw`"stderr":{"bytes":0,"sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","tail":"","tail_redactions":0,"tail_truncated":false},`
      + String.raw`"stdout":{"bytes":18234,"sha256":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","tail":"ok  \texample.com/widgets/api\t1.204s\nok  \texample.com/widgets/store\t0.811s\n","tail_redactions":0,"tail_truncated":true}},`
      + String.raw`"schema":"claim-check.receipt.v2","signed_at":"2026-10-06T09:00:03.120Z"}`;
    expect(canonicalize(payload)).toBe(expected);

    // The ID is the base32 of the first 16 bytes of SHA-256 over exactly that text (Node's own hash and base32 check here).
    const digest = await sha256(new TextEncoder().encode(expected));
    const id = await receiptId(payload);
    expect(id).toMatch(/^rcpt_[a-z2-7]{26}$/);
    expect(id).toBe(`rcpt_${base32Reference(digest.subarray(0, 16))}`);

    const reverse = (value: JsonValue): JsonValue => {
      if (Array.isArray(value)) return value.map(reverse);
      if (value === null || typeof value !== "object") return value;
      return Object.fromEntries(Object.keys(value).reverse().map((key) => [key, reverse(value[key])]));
    };
    const reordered = reverse(payload);
    expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(payload));
    expect(canonicalize(reordered)).toBe(expected);
    expect(await receiptId(reordered)).toBe(id);
  });
});

// Bit-by-bit RFC 4648 base32 written separately from the module, used only to cross-check the run payload ID.
function base32Reference(bytes: Uint8Array): string {
  const bits = [...bytes].map((byte) => byte.toString(2).padStart(8, "0")).join("");
  const padded = bits.padEnd(Math.ceil(bits.length / 5) * 5, "0");
  return (padded.match(/.{5}/g) ?? []).map((group) => "abcdefghijklmnopqrstuvwxyz234567"[parseInt(group, 2)]).join("");
}
