// Timestamp parsing for signed statements and requests.

const UTC_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Epoch ms of a v2 wire time, RFC 3339 UTC with exactly three fraction digits (2026-10-06T09:00:03.120Z); otherwise null. */
export function parseUtcMillis(text: string): number | null {
  if (!UTC_MILLIS.test(text)) return null;
  const ms = Date.parse(text);
  // The round trip rejects calendar-invalid values such as February 30.
  return Number.isNaN(ms) || new Date(ms).toISOString() !== text ? null : ms;
}

export const toUtcMillis = (ms: number): string => new Date(ms).toISOString();
