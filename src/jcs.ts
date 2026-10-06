// Strict JSON parsing and RFC 8785 (JCS) canonicalization for signed payloads.
// The v2 payload domain has no floats: every number is an integer within ±2^53.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type JsonErrorCode =
  | "invalid_utf8" | "syntax" | "too_deep" | "duplicate_key" | "non_integer"
  | "out_of_range" | "negative_zero" | "lone_surrogate" | "unsupported_value";

export class JsonError extends Error {
  readonly code: JsonErrorCode;
  constructor(code: JsonErrorCode, message: string) {
    super(message);
    this.name = "JsonError";
    this.code = code;
  }
}

const MAX_DEPTH = 64;
const MAX_INTEGER = 2 ** 53;
const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;
const ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xdc00 && unit <= 0xdfff) return true;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    }
  }
  return false;
}

function decodeUtf8(bytes: Uint8Array): string {
  // ignoreBOM keeps a leading U+FEFF in the text, so the parser rejects it.
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new JsonError("invalid_utf8", "The body is not valid UTF-8."); }
}

/** Parses RFC 8259 JSON, rejecting duplicate keys, non-integer or out-of-range numbers, -0 and lone surrogates. */
export function parseJson(input: string | Uint8Array): JsonValue {
  const text = typeof input === "string" ? input : decodeUtf8(input);
  let pos = 0;

  const fail = (code: JsonErrorCode, message: string): never => { throw new JsonError(code, `${message} at offset ${pos}.`); };
  const skipWhitespace = () => {
    while (pos < text.length) {
      const c = text.charCodeAt(pos);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
      pos++;
    }
  };
  const expect = (char: string) => {
    skipWhitespace();
    if (text[pos] !== char) fail("syntax", `Expected '${char}'`);
    pos++;
  };

  const parseString = (): string => {
    pos++;
    let out = "";
    let chunk = pos;
    for (;;) {
      if (pos >= text.length) fail("syntax", "Unterminated string");
      const c = text.charCodeAt(pos);
      if (c === 0x22) break;
      if (c < 0x20) fail("syntax", "Unescaped control character in string");
      if (c !== 0x5c) { pos++; continue; }
      out += text.slice(chunk, pos);
      const escape = text[pos + 1];
      if (escape === "u") {
        const hex = text.slice(pos + 2, pos + 6);
        if (!HEX4.test(hex)) fail("syntax", "Invalid \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        pos += 6;
      } else {
        if (escape === undefined || !(escape in ESCAPES)) fail("syntax", "Invalid escape");
        out += ESCAPES[escape];
        pos += 2;
      }
      chunk = pos;
    }
    out += text.slice(chunk, pos);
    pos++;
    if (hasLoneSurrogate(out)) fail("lone_surrogate", "String contains a lone surrogate");
    return out;
  };

  const parseNumber = (): number => {
    NUMBER.lastIndex = pos;
    const match = NUMBER.exec(text);
    if (!match) return fail("syntax", "Invalid number");
    if (match[1] !== undefined || match[2] !== undefined) fail("non_integer", "Numbers must be integers without fraction or exponent");
    const literal = match[0];
    if (literal === "-0") fail("negative_zero", "-0 is not allowed");
    const magnitude = BigInt(literal.startsWith("-") ? literal.slice(1) : literal);
    if (magnitude > BigInt(MAX_INTEGER)) fail("out_of_range", "Integer is outside +/-2^53");
    pos += literal.length;
    return Number(literal);
  };

  const parseValue = (depth: number): JsonValue => {
    skipWhitespace();
    const c = text[pos];
    if (c === "{" || c === "[") {
      if (depth >= MAX_DEPTH) fail("too_deep", "Nesting is too deep");
      return c === "{" ? parseObject(depth + 1) : parseArray(depth + 1);
    }
    if (c === '"') return parseString();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return parseNumber();
    for (const [word, value] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(word, pos)) { pos += word.length; return value; }
    }
    return fail("syntax", "Unexpected character");
  };

  const parseObject = (depth: number): { [key: string]: JsonValue } => {
    pos++;
    const result: { [key: string]: JsonValue } = {};
    const seen = new Set<string>();
    skipWhitespace();
    if (text[pos] === "}") { pos++; return result; }
    for (;;) {
      skipWhitespace();
      if (text[pos] !== '"') fail("syntax", "Expected a string key");
      const key = parseString();
      if (seen.has(key)) fail("duplicate_key", `Duplicate key ${JSON.stringify(key)}`);
      seen.add(key);
      expect(":");
      // defineProperty keeps keys such as "__proto__" as plain own properties.
      Object.defineProperty(result, key, { value: parseValue(depth), enumerable: true, writable: true, configurable: true });
      skipWhitespace();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "}") { pos++; return result; }
      fail("syntax", "Expected ',' or '}'");
    }
  };

  const parseArray = (depth: number): JsonValue[] => {
    pos++;
    const result: JsonValue[] = [];
    skipWhitespace();
    if (text[pos] === "]") { pos++; return result; }
    for (;;) {
      result.push(parseValue(depth));
      skipWhitespace();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "]") { pos++; return result; }
      fail("syntax", "Expected ',' or ']'");
    }
  };

  const value = parseValue(0);
  skipWhitespace();
  if (pos !== text.length) fail("syntax", "Unexpected trailing characters");
  return value;
}

/** RFC 8785 canonical JSON text. Rejects anything outside the integer-only JSON domain. */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new JsonError("lone_surrogate", "String contains a lone surrogate.");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new JsonError("non_integer", "Only integers can be canonicalized.");
    if (Object.is(value, -0)) throw new JsonError("negative_zero", "-0 cannot be canonicalized.");
    if (Math.abs(value) > MAX_INTEGER) throw new JsonError("out_of_range", "Integer is outside +/-2^53.");
    return String(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, (item) => canonicalize(item)).join(",")}]`;
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new JsonError("unsupported_value", "Only plain objects can be canonicalized.");
    const record = value as Record<string, unknown>;
    // Array.prototype.sort without a comparator orders strings by UTF-16 code units, as RFC 8785 requires.
    const members = Object.keys(record).sort().map((key) => `${canonicalize(key)}:${canonicalize(record[key])}`);
    return `{${members.join(",")}}`;
  }
  throw new JsonError("unsupported_value", `A ${typeof value} cannot be canonicalized.`);
}

/** UTF-8 bytes of canonicalize(value). */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
