// Response helpers and request-body reading shared by every action.
import { parseJson, JsonError, type JsonValue } from "./jcs";

export type JsonObject = { [key: string]: JsonValue };

export const MAX_BODY_BYTES = 65_536;

export const json = (body: unknown, status = 200, headers = new Headers()): Response => {
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers });
};

/** v1's error body: { error, hint }. */
export const error = (status: number, code: string, hint: string, headers?: Headers) => json({ error: code, hint }, status, headers);

export const invalidRequest = (hint: string) => error(400, "invalid_request", hint);

/** Reads the body, counting bytes as they stream in. Returns null once it exceeds maxBytes; Content-Length is never consulted. */
export async function readBody(request: Request, maxBytes = MAX_BODY_BYTES): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Strict parse (duplicate keys, floats and invalid UTF-8 rejected); null unless the body is a JSON object. */
export function parseJsonObject(body: Uint8Array): JsonObject | null {
  try {
    const value = parseJson(body);
    return isJsonObject(value) ? value : null;
  } catch (cause) {
    if (cause instanceof JsonError) return null;
    throw cause;
  }
}

export function hasOnlyKeys(object: JsonObject, allowed: readonly string[]): boolean {
  return Object.keys(object).every((key) => allowed.includes(key));
}
