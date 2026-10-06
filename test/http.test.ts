import { describe, it, expect } from "vitest";
import { MAX_BODY_BYTES, parseJsonObject, readBody } from "../src/http";

const URL_ = "https://claim-check.ohmygraph.workers.dev/api/agent/actions/list-keys";

function streamed(chunks: Uint8Array[], headers: Record<string, string> = {}): { request: Request; pulled: () => number } {
  let index = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else controller.close();
    },
  });
  const request = new Request(URL_, { method: "POST", body, headers, duplex: "half" } as RequestInit);
  return { request, pulled: () => index };
}

describe("readBody", () => {
  it("returns the body up to exactly 64 KB", async () => {
    const bytes = await readBody(new Request(URL_, { method: "POST", body: new Uint8Array(MAX_BODY_BYTES).fill(0x20) }));
    expect(bytes?.byteLength).toBe(65_536);
  });

  it("returns null one byte over 64 KB", async () => {
    expect(await readBody(new Request(URL_, { method: "POST", body: new Uint8Array(MAX_BODY_BYTES + 1) }))).toBeNull();
  });

  it("returns an empty body when there is none", async () => {
    expect(await readBody(new Request(URL_, { method: "POST" }))).toEqual(new Uint8Array(0));
  });

  it("counts streamed bytes, ignores a small Content-Length, and stops reading once over the cap", async () => {
    const chunk = new Uint8Array(16_384);
    const { request, pulled } = streamed(Array.from({ length: 10 }, () => chunk), { "Content-Length": "2" });
    expect(await readBody(request)).toBeNull();
    // The fifth chunk crosses 64 KB; the stream is cancelled rather than drained.
    expect(pulled()).toBeLessThan(10);
  });

  it("joins chunks in order", async () => {
    const { request } = streamed([new TextEncoder().encode('{"a"'), new TextEncoder().encode(":1}")]);
    expect(new TextDecoder().decode((await readBody(request))!)).toBe('{"a":1}');
  });
});

describe("parseJsonObject", () => {
  const parse = (text: string) => parseJsonObject(new TextEncoder().encode(text));

  it("accepts an object and rejects everything else, including duplicate keys", () => {
    expect(parse('{"a":1}')).toEqual({ a: 1 });
    for (const text of ["", "[]", "null", '"x"', "{", '{"a":1,"a":1}', '{"a":1.5}']) expect(parse(text), text).toBeNull();
  });
});
