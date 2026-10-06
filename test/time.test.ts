import { describe, it, expect } from "vitest";
import { parseRfc3339, parseUtcMillis } from "../src/time";

const at = (text: string) => Date.parse(text);

describe("parseUtcMillis", () => {
  it("accepts only RFC 3339 UTC with exactly three fraction digits", () => {
    expect(parseUtcMillis("2026-10-06T09:00:03.120Z")).toBe(at("2026-10-06T09:00:03.120Z"));
    expect(parseUtcMillis("2024-02-29T00:00:00.000Z")).toBe(at("2024-02-29T00:00:00.000Z"));
    for (const text of ["2026-10-06T09:00:03Z", "2026-10-06T09:00:03.12Z", "2026-10-06T09:00:03.1200Z", "2026-10-06t09:00:03.120Z",
      "2026-10-06T09:00:03.120z", "2026-10-06T09:00:03.120+00:00", "2026-02-29T00:00:00.000Z", "2026-10-06T24:00:00.000Z", " 2026-10-06T09:00:03.120Z"]) {
      expect(parseUtcMillis(text), text).toBeNull();
    }
  });
});

describe("parseRfc3339", () => {
  it("accepts offsets, lowercase separators and any fraction length, truncating past milliseconds", () => {
    expect(parseRfc3339("2026-10-06T09:00:03.120Z")).toBe(at("2026-10-06T09:00:03.120Z"));
    expect(parseRfc3339("2026-10-06T09:00:03Z")).toBe(at("2026-10-06T09:00:03.000Z"));
    expect(parseRfc3339("2026-10-06t09:00:03.1z")).toBe(at("2026-10-06T09:00:03.100Z"));
    expect(parseRfc3339("2026-10-06T09:00:03.123999999Z")).toBe(at("2026-10-06T09:00:03.123Z"));
    expect(parseRfc3339("2026-10-06T11:30:00+02:30")).toBe(at("2026-10-06T09:00:00.000Z"));
    expect(parseRfc3339("2026-10-05T23:00:00-10:00")).toBe(at("2026-10-06T09:00:00.000Z"));
    expect(parseRfc3339("2024-02-29T00:00:00Z")).toBe(at("2024-02-29T00:00:00.000Z"));
    expect(parseRfc3339("0050-01-01T00:00:00Z")).toBe(at("0050-01-01T00:00:00.000Z"));
  });

  it("rejects everything else", () => {
    for (const text of ["", "yesterday", "2026-10-06", "2026-10-06T09:00:00", "2026-10-06 09:00:00Z", "2026-10-06T09:00Z", "2026-10-06T09:00:00.Z",
      "2026-10-06T09:00:00+0200", "2026-10-06T09:00:00+24:00", "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-04-31T00:00:00Z",
      "2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-10-06T24:00:00Z", "2026-10-06T23:60:00Z", "2016-12-31T23:59:60Z", "2026-10-06T09:00:00Z "]) {
      expect(parseRfc3339(text), text).toBeNull();
    }
  });
});
