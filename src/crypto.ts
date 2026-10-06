// Encodings, ID derivation and ed25519 verification for v2 keys and receipts.
// WebCrypto only: nothing here imports node: modules.
import { canonicalBytes, type JsonValue } from "./jcs";

export type EncodingErrorCode = "bad_prefix" | "bad_length" | "bad_base64url" | "non_canonical";

export class EncodingError extends Error {
  readonly code: EncodingErrorCode;
  constructor(code: EncodingErrorCode, message: string) {
    super(message);
    this.name = "EncodingError";
    this.code = code;
  }
}

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const ED25519_PREFIX = "ed25519:";
// The order of the ed25519 base point; a canonical signature has S < L.
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

function encodeBits(bytes: Uint8Array, alphabet: string, width: number): string {
  let out = "", value = 0, bits = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= width) { bits -= width; out += alphabet[(value >>> bits) & ((1 << width) - 1)]; }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(value << (width - bits)) & ((1 << width) - 1)];
  return out;
}

/** base64url without padding (RFC 4648 section 5). */
export function base64urlEncode(bytes: Uint8Array): string {
  return encodeBits(bytes, BASE64URL, 6);
}

/** Strict base64url without padding: the input must be exactly what base64urlEncode would produce. */
export function base64urlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new EncodingError("bad_base64url", "Invalid base64url length.");
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let value = 0, bits = 0, index = 0;
  for (let i = 0; i < text.length; i++) {
    const digit = BASE64URL.indexOf(text[i]);
    if (digit < 0) throw new EncodingError("bad_base64url", "Character outside the base64url alphabet.");
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) { bits -= 8; out[index++] = (value >>> bits) & 0xff; }
    value &= (1 << bits) - 1;
  }
  if (base64urlEncode(out) !== text) throw new EncodingError("non_canonical", "Non-zero trailing bits in base64url.");
  return out;
}

/** Lowercase RFC 4648 base32 without padding. */
export function base32Encode(bytes: Uint8Array): string {
  return encodeBits(bytes, BASE32, 5);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** "ck_" + base32 of the first 16 bytes of SHA-256(raw 32-byte public key). */
export async function keyId(rawPublicKey: Uint8Array): Promise<string> {
  if (rawPublicKey.length !== 32) throw new EncodingError("bad_length", "An ed25519 public key is 32 bytes.");
  return `ck_${base32Encode((await sha256(rawPublicKey)).subarray(0, 16))}`;
}

/** "rcpt_" + base32 of the first 16 bytes of SHA-256(UTF-8 JCS(payload)). */
export async function receiptId(payload: JsonValue): Promise<string> {
  return `rcpt_${base32Encode((await sha256(canonicalBytes(payload))).subarray(0, 16))}`;
}

function parseEd25519(text: string, byteLength: number): Uint8Array {
  if (!text.startsWith(ED25519_PREFIX)) throw new EncodingError("bad_prefix", `Expected the ${ED25519_PREFIX} prefix.`);
  const encoded = text.slice(ED25519_PREFIX.length);
  if (encoded.length !== Math.ceil((byteLength * 8) / 6)) throw new EncodingError("bad_length", `Expected base64url of ${byteLength} bytes.`);
  return base64urlDecode(encoded);
}

/** "ed25519:" + base64url of a raw 32-byte public key. */
export function parsePublicKey(text: string): Uint8Array {
  return parseEd25519(text, 32);
}

/** "ed25519:" + base64url of a 64-byte signature, rejecting every non-canonical encoding and S >= L. */
export function parseSignature(text: string): Uint8Array {
  const bytes = parseEd25519(text, 64);
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(bytes[i]);
  if (s >= ED25519_L) throw new EncodingError("non_canonical", "Signature scalar S is not below the group order.");
  return bytes;
}

/** Verifies an ed25519 signature with WebCrypto. Any failure, including an unusable key, is false. */
export async function verifyEd25519(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, message);
  } catch {
    return false;
  }
}
