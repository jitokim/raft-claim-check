import type { Session } from "../src/context";

export const session = (overrides: Partial<Session> = {}): Session => ({
  id_hash: "hash", server_id: "srv_a", server_slug: "a", server_name: "A", principal_id: "agent_a", principal_type: "agent",
  display_name: null, scopes: "openid profile", expires_at: "2026-10-07T09:00:00.000Z", ...overrides,
});
