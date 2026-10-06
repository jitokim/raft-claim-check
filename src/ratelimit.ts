// Sliding-window rate limits (docs/design-v2.md, ## Rate limits and abuse).
import { error } from "./http";
import type { Session } from "./context";
import type { RateAction, RateWindow, Store } from "./store";

const MINUTE = 60_000;
const HOUR = 3_600_000;

export const RATE_LIMITS: Readonly<Record<RateAction, readonly RateWindow[]>> = {
  submit: [
    { scope: "principal", windowMs: MINUTE, max: 30 },
    { scope: "principal", windowMs: HOUR, max: 600 },
    { scope: "server", windowMs: HOUR, max: 3000 },
  ],
  register: [
    { scope: "principal", windowMs: HOUR, max: 5 },
    { scope: "server", windowMs: HOUR, max: 30 },
  ],
  revoke: [{ scope: "principal", windowMs: HOUR, max: 10 }],
  read: [{ scope: "principal", windowMs: MINUTE, max: 120 }],
};

const HINTS: Readonly<Record<RateAction, string>> = {
  submit: "Receipt submission limit exceeded; retry after the indicated delay.",
  register: "Key registration limit exceeded; retry after the indicated delay.",
  revoke: "Key revocation limit exceeded; retry after the indicated delay.",
  read: "Read limit exceeded; retry after the indicated delay.",
};

/**
 * Reserves one unit of `action` for the session's principal. Returns undefined on success, or a 429 whose
 * Retry-After comes from the oldest reservation still inside the exhausted window. Nothing is stored on refusal.
 */
export async function reserve(store: Store, action: RateAction, session: Session, now: number): Promise<Response | undefined> {
  const reservation = { action, serverId: session.server_id, principalId: session.principal_id, nowMs: now };
  const windows = RATE_LIMITS[action];
  if (await store.reserve(reservation, windows)) return undefined;
  const usage = await store.windowUsage(reservation, windows);
  let waitMs = 0;
  usage.forEach(({ count, oldest }, index) => {
    if (count >= windows[index].max && oldest !== null) waitMs = Math.max(waitMs, oldest + windows[index].windowMs - now);
  });
  const headers = new Headers({ "Retry-After": String(Math.max(1, Math.ceil(waitMs / 1000))) });
  return error(429, "rate_limited", HINTS[action], headers);
}
