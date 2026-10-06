export interface Env {
  DB: D1Database;
  CANONICAL_ORIGIN: string;
  RAFT_CLIENT_ID: string;
  RAFT_CLIENT_SECRET: string;
  SESSION_SECRET: string;
}

export const CALLBACK_PATH = "/auth/agent/callback";
export const MANIFEST_PATH = "/.well-known/raft-agent-manifest.json";
export const SESSION_COOKIE = "cc_session";
export const SESSION_SECONDS = 86_400;
