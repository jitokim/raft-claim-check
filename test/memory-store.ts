// In-memory fake of the Store port. test/store.test.ts runs the same contract against it and against D1Store.
import type { KeyRow, NewKey, RateAction, RateWindow, Reservation, Revocation, Store, WindowUsage } from "../src/store";

interface ReservationRow { serverId: string; principalId: string; action: RateAction; units: number; createdAt: number }

export class MemoryStore implements Store {
  readonly reservations: ReservationRow[] = [];
  readonly keys: KeyRow[] = [];

  private inWindow(reservation: Reservation, window: RateWindow): ReservationRow[] {
    return this.reservations.filter((row) =>
      row.serverId === reservation.serverId
      && (window.scope === "server" || row.principalId === reservation.principalId)
      && row.action === reservation.action
      && row.createdAt > reservation.nowMs - window.windowMs);
  }

  async reserve(reservation: Reservation, windows: readonly RateWindow[]): Promise<boolean> {
    if (!windows.every((window) => this.inWindow(reservation, window).length < window.max)) return false;
    this.reservations.push({ serverId: reservation.serverId, principalId: reservation.principalId, action: reservation.action, units: 1, createdAt: reservation.nowMs });
    return true;
  }

  async windowUsage(reservation: Reservation, windows: readonly RateWindow[]): Promise<WindowUsage[]> {
    return windows.map((window) => {
      const rows = this.inWindow(reservation, window);
      return { count: rows.length, oldest: rows.length ? Math.min(...rows.map((row) => row.createdAt)) : null };
    });
  }

  async getKey(keyId: string): Promise<KeyRow | null> {
    const row = this.keys.find((key) => key.key_id === keyId);
    return row ? { ...row } : null;
  }

  async insertKey(key: NewKey, maxActive: number): Promise<boolean> {
    if (this.keys.some((row) => row.key_id === key.key_id || row.public_key === key.public_key)) return false;
    const active = this.keys.filter((row) => row.server_id === key.server_id && row.principal_id === key.principal_id && row.revoked_at === null);
    if (active.length >= maxActive) return false;
    this.keys.push({ ...key, revoked_at: null, revoked_reason: null, compromised_since: null });
    return true;
  }

  async listKeys(serverId: string, principalId: string): Promise<KeyRow[]> {
    const descending = (a: string, b: string) => (a < b ? 1 : a > b ? -1 : 0);
    return this.keys
      .filter((row) => row.server_id === serverId && row.principal_id === principalId)
      .sort((a, b) => descending(a.registered_at, b.registered_at) || descending(a.key_id, b.key_id))
      .map((row) => ({ ...row }));
  }

  async revokeKey(revocation: Revocation): Promise<boolean> {
    const row = this.keys.find((key) => key.key_id === revocation.keyId && key.server_id === revocation.serverId && key.principal_id === revocation.principalId && key.revoked_at === null);
    if (!row) return false;
    row.revoked_at = revocation.revokedAt;
    row.revoked_reason = revocation.reason;
    row.compromised_since = revocation.compromisedSince;
    return true;
  }
}
