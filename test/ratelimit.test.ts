import { describe, it, expect } from "vitest";
import { RATE_LIMITS, reserve } from "../src/ratelimit";
import { D1Store, type RateAction, type Store } from "../src/store";
import { session } from "./helpers";
import { MemoryStore } from "./memory-store";
import { migratedDatabase } from "./sqlite-d1";

const T0 = Date.UTC(2026, 9, 6, 9, 0, 0);
const MINUTE = 60_000;
const HOUR = 3_600_000;

it("uses the caps from docs/design-v2.md", () => {
  expect(RATE_LIMITS).toEqual({
    submit: [{ scope: "principal", windowMs: MINUTE, max: 30 }, { scope: "principal", windowMs: HOUR, max: 600 }, { scope: "server", windowMs: HOUR, max: 3000 }],
    register: [{ scope: "principal", windowMs: HOUR, max: 5 }, { scope: "server", windowMs: HOUR, max: 30 }],
    revoke: [{ scope: "principal", windowMs: HOUR, max: 10 }],
    read: [{ scope: "principal", windowMs: MINUTE, max: 120 }],
  });
});

const implementations: [string, () => Store][] = [
  ["MemoryStore", () => new MemoryStore()],
  ["D1Store on node:sqlite", () => new D1Store(migratedDatabase().d1)],
];

describe.each(implementations)("reserve on %s", (_name, makeStore) => {
  async function fill(store: Store, action: RateAction, count: number, now: number, who = session()) {
    for (let i = 0; i < count; i++) expect(await reserve(store, action, who, now), `reservation ${i + 1}`).toBeUndefined();
  }

  async function expect429(store: Store, action: RateAction, now: number, retryAfter: number, who = session()) {
    const response = await reserve(store, action, who, now);
    expect(response?.status).toBe(429);
    expect(response?.headers.get("Retry-After")).toBe(String(retryAfter));
    expect(await response?.json()).toEqual({ error: "rate_limited", hint: expect.any(String) });
  }

  it("read: 120 per minute per agent, Retry-After from the oldest reservation in the window (v1 behaviour)", async () => {
    const store = makeStore();
    await fill(store, "read", 1, T0);
    await fill(store, "read", 119, T0 + 20_000);
    await expect429(store, "read", T0 + 30_000, 30);
    await expect429(store, "read", T0 + 59_001, 1);
    expect(await reserve(store, "read", session(), T0 + MINUTE)).toBeUndefined();
    // Another agent on the same server has its own budget.
    expect(await reserve(store, "read", session({ principal_id: "agent_b" }), T0 + MINUTE)).toBeUndefined();
  });

  it("register: 5 per hour per agent and 30 per hour per server", async () => {
    const store = makeStore();
    await fill(store, "register", 5, T0);
    await expect429(store, "register", T0 + 1000, 3599);
    for (const principal of ["b", "c", "d", "e", "f"]) await fill(store, "register", 5, T0 + 10 * MINUTE, session({ principal_id: `agent_${principal}` }));
    await expect429(store, "register", T0 + 20 * MINUTE, 40 * 60, session({ principal_id: "agent_g" }));
    expect(await reserve(store, "register", session({ principal_id: "agent_g", server_id: "srv_b" }), T0 + 20 * MINUTE)).toBeUndefined();
  });

  it("revoke: 10 per hour per agent", async () => {
    const store = makeStore();
    await fill(store, "revoke", 10, T0);
    await expect429(store, "revoke", T0 + 30 * MINUTE, 30 * 60);
    expect(await reserve(store, "revoke", session(), T0 + HOUR)).toBeUndefined();
  });

  it("submit: 30 per minute and 600 per hour per agent, 3000 per hour per server; Retry-After is the longest exhausted window's wait", async () => {
    const store = makeStore();
    await fill(store, "submit", 30, T0);
    await expect429(store, "submit", T0 + 15_000, 45);
    // 20 batches of 30, one per two minutes, reach the hourly 600 without tripping the minute cap.
    for (let batch = 1; batch < 20; batch++) await fill(store, "submit", 30, T0 + batch * 2 * MINUTE);
    await expect429(store, "submit", T0 + 40 * MINUTE, 20 * 60);
    // Both windows exhausted: the hour window's wait is longer and wins.
    await expect429(store, "submit", T0 + 38 * MINUTE + 1000, 22 * 60 - 1);
  }, 30_000);

  it("submit: the server-wide hourly cap of 3000", async () => {
    const store = makeStore();
    for (let p = 0; p < 5; p++) {
      for (let batch = 0; batch < 20; batch++) await fill(store, "submit", 30, T0 + batch * 2 * MINUTE, session({ principal_id: `agent_${p}` }));
    }
    await expect429(store, "submit", T0 + 50 * MINUTE, 10 * 60, session({ principal_id: "agent_new" }));
  }, 60_000);
});
