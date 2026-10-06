// Timestamp parsing for signed statements and requests.

const UTC_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Epoch ms of a v2 wire time, RFC 3339 UTC with exactly three fraction digits (2026-10-06T09:00:03.120Z); otherwise null. */
export function parseUtcMillis(text: string): number | null {
  if (!UTC_MILLIS.test(text)) return null;
  const ms = Date.parse(text);
  // The round trip rejects calendar-invalid values such as February 30.
  return Number.isNaN(ms) || new Date(ms).toISOString() !== text ? null : ms;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

const daysInMonth = (year: number, month: number) =>
  month === 2 ? ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;

/**
 * Epoch ms of any RFC 3339 date-time (offsets and any number of fraction digits allowed); otherwise null.
 * Digits past milliseconds are truncated. Leap seconds (:60) are rejected.
 */
export function parseRfc3339(text: string): number | null {
  const match = RFC3339.exec(text);
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) return null;
  let offsetMs = 0;
  const zone = match[8];
  if (zone !== "Z" && zone !== "z") {
    const offsetHours = Number(zone.slice(1, 3)), offsetMinutes = Number(zone.slice(4, 6));
    if (offsetHours > 23 || offsetMinutes > 59) return null;
    offsetMs = (zone[0] === "-" ? -1 : 1) * (offsetHours * 60 + offsetMinutes) * 60_000;
  }
  const date = new Date(0);
  // setUTCFullYear, unlike Date.UTC, does not map years 0-99 to 1900-1999.
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, Number((match[7] ?? "").slice(0, 3).padEnd(3, "0")));
  return date.getTime() - offsetMs;
}

export const toUtcMillis = (ms: number): string => new Date(ms).toISOString();
