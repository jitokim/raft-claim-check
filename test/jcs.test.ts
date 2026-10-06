import { describe, it, expect } from "vitest";
import { canonicalBytes, canonicalize, JsonError, parseJson, type NumberIssue } from "../src/jcs";

// U("20ac") is the six-character JSON escape backslash-u-2-0-a-c; ch() builds the decoded characters.
// Escapes and non-ASCII characters are built in code so the source file stays plain ASCII.
const U = (hex: string) => "\\" + "u" + hex;
const ch = (...codes: number[]) => String.fromCharCode(...codes);

const jcs = (text: string) => canonicalize(parseJson(text));
const errorCode = (fn: () => unknown): string | undefined => {
  try { fn(); } catch (error) { return error instanceof JsonError ? error.code : `not a JsonError: ${String(error)}`; }
  return undefined;
};

describe("RFC 8785 section 3.2.3 sorting example", () => {
  // The RFC's input, member for member.
  const input = [
    "{",
    `  "${U("20ac")}": "Euro Sign",`,
    `  "\\r": "Carriage Return",`,
    `  "${U("fb33")}": "Hebrew Letter Dalet With Dagesh",`,
    `  "1": "One",`,
    `  "${U("d83d")}${U("de00")}": "Emoji: Grinning Face",`,
    `  "${U("0080")}": "Control",`,
    `  "${U("00f6")}": "Latin Small Letter O With Diaeresis"`,
    "}",
  ].join("\n");

  it("orders members by UTF-16 code units as the RFC lists them", () => {
    // Read the order from the text: a JS object would hoist the integer-like key "1".
    const text = jcs(input);
    const order = [
      "Carriage Return",
      "One",
      "Control",
      "Latin Small Letter O With Diaeresis",
      "Euro Sign",
      "Emoji: Grinning Face",
      "Hebrew Letter Dalet With Dagesh",
    ];
    const positions = order.map((value) => text.indexOf(`"${value}"`));
    expect(positions.every((position) => position > 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("serializes to the exact canonical text", () => {
    // Only \r is escaped; every other key is emitted as the raw character.
    expect(jcs(input)).toBe(
      `{"\\r":"Carriage Return","1":"One","${ch(0x80)}":"Control","${ch(0xf6)}":"Latin Small Letter O With Diaeresis",`
      + `"${ch(0x20ac)}":"Euro Sign","${ch(0xd83d, 0xde00)}":"Emoji: Grinning Face","${ch(0xfb33)}":"Hebrew Letter Dalet With Dagesh"}`,
    );
  });
});

describe("RFC 8785 section 3.2.2 example", () => {
  // The RFC's "string" member: U+20AC $ U+000F U+000A A ' U+0042 U+0022 U+005C, then \\ \" \/ as two-character escapes.
  const stringMember = `"string": "${U("20ac")}$${U("000F")}${U("000a")}A'${U("0042")}${U("0022")}${U("005c")}\\\\\\"\\/"`;
  const literalsMember = `"literals": [null, true, false]`;
  // The full RFC input, including its floating-point "numbers" member.
  const fullInput = [
    "{",
    `  "numbers": [333333333.33333329, 1E30, 4.50,`,
    `              2e-3, 0.000000000000000000000000001],`,
    `  ${stringMember},`,
    `  ${literalsMember}`,
    "}",
  ].join("\n");
  const withoutNumbers = ["{", `  ${stringMember},`, `  ${literalsMember}`, "}"].join("\n");
  // The RFC output is {"literals":[null,true,false],"numbers":[...],"string":"<euro>$\u000f\nA'B\"\\\\\"/"}
  // (the euro sign raw, U+000F as a lowercase escape); these are its literals and string members.
  const expected = `{"literals":[null,true,false],"string":"${ch(0x20ac)}$${U("000f")}\\nA'B\\"\\\\\\\\\\"/"}`;

  it("builds the RFC string member as printed", () => {
    expect(stringMember).toBe('"string": "' + "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/" + '"');
    expect(expected.slice(expected.indexOf('"string"'))).toBe('"string":"' + ch(0x20ac) + "$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}");
  });

  it("canonicalizes the literals and string members to the RFC output", () => {
    expect(jcs(withoutNumbers)).toBe(expected);
  });

  it("encodes the canonical text as UTF-8", () => {
    const bytes = canonicalBytes(parseJson(withoutNumbers));
    expect(Buffer.from(bytes).toString("utf8")).toBe(expected);
    // The euro sign U+20AC is e2 82 ac in UTF-8, right after the opening quote of the string value.
    const at = Buffer.from(bytes).indexOf(Buffer.from('"string":"', "utf8")) + '"string":"'.length;
    expect([...bytes.subarray(at, at + 3)]).toEqual([0xe2, 0x82, 0xac]);
  });

  it("rejects the full input because it contains floats", () => {
    expect(errorCode(() => parseJson(fullInput))).toBe("non_integer");
  });
});

describe("strict parsing", () => {
  it("rejects duplicate keys", () => {
    expect(errorCode(() => parseJson('{"a":1,"a":2}'))).toBe("duplicate_key");
    expect(errorCode(() => parseJson('{"x":{"a":1,"b":2,"a":3}}'))).toBe("duplicate_key");
  });

  it("rejects a key written once plainly and once with a \\u escape", () => {
    const escapedA = `{"a":1,"${U("0061")}":2}`;
    expect(escapedA).toBe('{"a":1,"\\u0061":2}');
    expect(errorCode(() => parseJson(escapedA))).toBe("duplicate_key");
    expect(errorCode(() => parseJson(`{"key_id":"x","key${U("005f")}id":"y"}`))).toBe("duplicate_key");
    expect(parseJson(`{"a":1,"${U("0062")}":2}`)).toEqual({ a: 1, b: 2 });
  });

  it("records number-domain issues with their paths instead of throwing when asked to", () => {
    const issues: NumberIssue[] = [];
    const value = parseJson('{"a":{"b":[1,2.0,-0]},"c":9007199254740993,"d":1e3,"e":7}', issues);
    expect(value).toEqual({ a: { b: [1, 2, -0] }, c: 9007199254740992, d: 1000, e: 7 });
    expect(issues).toEqual([
      { path: "a.b[1]", code: "non_integer" },
      { path: "a.b[2]", code: "negative_zero" },
      { path: "c", code: "out_of_range" },
      { path: "d", code: "non_integer" },
    ]);
    // Everything else is still fatal in that mode.
    expect(errorCode(() => parseJson('{"a":1.5,"a":2}', []))).toBe("duplicate_key");
    expect(errorCode(() => parseJson("[1.5", []))).toBe("syntax");
  });

  it("rejects the floats 1.0, 1e3 and 0.5", () => {
    for (const text of ["1.0", "1e3", "0.5", "[1.0]", '{"n":1e3}', '{"n":0.5}', "1E3", "1e-3", "-0.5"]) {
      expect(errorCode(() => parseJson(text)), text).toBe("non_integer");
    }
  });

  it("accepts integers up to +/-2^53 and rejects 2^53+1", () => {
    expect(parseJson("9007199254740992")).toBe(2 ** 53);
    expect(parseJson("-9007199254740992")).toBe(-(2 ** 53));
    expect(jcs("[9007199254740991,9007199254740992,-9007199254740992]")).toBe("[9007199254740991,9007199254740992,-9007199254740992]");
    expect(errorCode(() => parseJson("9007199254740993"))).toBe("out_of_range");
    expect(errorCode(() => parseJson("-9007199254740993"))).toBe("out_of_range");
    expect(errorCode(() => parseJson("100000000000000000000000"))).toBe("out_of_range");
  });

  it("rejects -0", () => {
    expect(errorCode(() => parseJson("-0"))).toBe("negative_zero");
    expect(errorCode(() => parseJson('{"n":-0}'))).toBe("negative_zero");
  });

  it("rejects lone surrogates", () => {
    const escaped = [`"${U("d800")}"`, `"${U("dc00")}"`, `"${U("dc00")}${U("d800")}"`, `"a${U("d83d")}"`, `"${U("d83d")}x${U("de00")}"`];
    for (const text of escaped) expect(errorCode(() => parseJson(text)), text).toBe("lone_surrogate");
    expect(errorCode(() => parseJson(`"${ch(0xd800)}"`)), "raw lone surrogate").toBe("lone_surrogate");
    expect(errorCode(() => parseJson(`{"${U("d800")}":1}`))).toBe("lone_surrogate");
    expect(parseJson(`"${U("d83d")}${U("de00")}"`)).toBe(ch(0xd83d, 0xde00));
  });

  it("rejects malformed RFC 8259 input", () => {
    const cases = ["", "01", "[01]", "+1", "1.", "-", "[1,]", '{"a":1,}', "{'a':1}", `"${ch(9)}"`, '"\\x41"', `"${U("00g0")}"`, "[1] 2", "nul", `${ch(0xfeff)}{}`, "NaN", '{"a" 1}'];
    for (const text of cases) expect(errorCode(() => parseJson(text)), JSON.stringify(text)).toBe("syntax");
  });

  it("rejects invalid UTF-8 and caps nesting depth", () => {
    expect(errorCode(() => parseJson(new Uint8Array([0x22, 0xc3, 0x28, 0x22])))).toBe("invalid_utf8");
    expect(errorCode(() => parseJson(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])))).toBe("syntax");
    expect(errorCode(() => parseJson("[".repeat(10_000) + "]".repeat(10_000)))).toBe("too_deep");
    expect(parseJson("[".repeat(64) + "]".repeat(64))).toBeDefined();
  });

  it("parses UTF-8 bytes and keeps __proto__ as an ordinary key", () => {
    const value = parseJson(new TextEncoder().encode(` {"__proto__": {"x": 1}, "b": [true, null, "${ch(0xe9)}"]} `)) as Record<string, unknown>;
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(Object.keys(value)).toEqual(["__proto__", "b"]);
    expect(canonicalize(value)).toBe(`{"__proto__":{"x":1},"b":[true,null,"${ch(0xe9)}"]}`);
  });
});

describe("canonicalize", () => {
  it("rejects non-integer numbers and values outside JSON", () => {
    expect(errorCode(() => canonicalize(0.5))).toBe("non_integer");
    expect(errorCode(() => canonicalize({ a: [1.5] }))).toBe("non_integer");
    expect(errorCode(() => canonicalize(Number.NaN))).toBe("non_integer");
    expect(errorCode(() => canonicalize(Number.POSITIVE_INFINITY))).toBe("non_integer");
    expect(errorCode(() => canonicalize(-0))).toBe("negative_zero");
    expect(errorCode(() => canonicalize(2 ** 53 + 2))).toBe("out_of_range");
    expect(errorCode(() => canonicalize(ch(0xd800)))).toBe("lone_surrogate");
    expect(errorCode(() => canonicalize(undefined))).toBe("unsupported_value");
    expect(errorCode(() => canonicalize({ a: undefined }))).toBe("unsupported_value");
    expect(errorCode(() => canonicalize(new Date(0)))).toBe("unsupported_value");
  });

  it("in the finite domain, writes numbers as RFC 8785 does and still rejects non-finite ones", () => {
    expect(canonicalize({ b: 1.5, a: [1e21, 1e-7, -0, 2 ** 60] }, "finite")).toBe('{"a":[1e+21,1e-7,0,1152921504606847000],"b":1.5}');
    expect(errorCode(() => canonicalize(Number.POSITIVE_INFINITY, "finite"))).toBe("out_of_range");
    expect(errorCode(() => canonicalize(Number.NaN, "finite"))).toBe("out_of_range");
    expect(Buffer.from(canonicalBytes([0.5], "finite")).toString("utf8")).toBe("[0.5]");
  });

  it("sorts nested members and serializes strings as JSON.stringify does", () => {
    const lineSeparator = ch(0x2028);
    expect(canonicalize({ b: [{ z: 1, a: `x${lineSeparator}y` }], a: { d: null, c: false } })).toBe(`{"a":{"c":false,"d":null},"b":[{"a":"x${lineSeparator}y","z":1}]}`);
    expect(canonicalize(ch(0, 0x1f) + '"\\/')).toBe(`"${U("0000")}${U("001f")}\\"\\\\/"`);
  });
});
