import manifest from "./manifest.json";
import type { ActionHandler, Session } from "./context";
import type { Env } from "./env";
import { CALLBACK_PATH, MANIFEST_PATH, SESSION_COOKIE, SESSION_SECONDS } from "./env";
import { error, json, readBody } from "./http";
import { listKeys, registerKey, revokeKey } from "./keys";
import { reserve } from "./ratelimit";
import { submitReceipt } from "./receipts";
import { D1Store } from "./store";

const canonicalOrigin = (env: Env) => env.CANONICAL_ORIGIN.replace(/\/$/, "");
const callbackUrl = (env: Env) => `${canonicalOrigin(env)}${CALLBACK_PATH}`;
const nowIso = () => new Date().toISOString();

async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function callback(request: Request, env: Env): Promise<Response> {
  const code = new URL(request.url).searchParams.get("code");
  if (!code) return error(400, "invalid_code", "The one-time authorization code is missing.");
  if (!env.RAFT_CLIENT_ID || !env.RAFT_CLIENT_SECRET || !env.SESSION_SECRET) return error(502, "exchange_failed", "Raft login is not configured.");

  let tokenUrl: string;
  try {
    const discovery = await fetch("https://api.raft.build/.well-known/openid-configuration", { signal: AbortSignal.timeout(10_000), redirect: "manual" });
    if (!discovery.ok) throw new Error("discovery unavailable");
    const config = await discovery.json() as { token_endpoint?: string };
    if (!config.token_endpoint || new URL(config.token_endpoint).origin !== "https://api.raft.build") throw new Error("invalid token endpoint");
    tokenUrl = config.token_endpoint;
  } catch {
    return error(502, "exchange_failed", "Raft login could not be reached.");
  }

  let token: { access_token?: string; scope?: string };
  try {
    const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: callbackUrl(env), client_id: env.RAFT_CLIENT_ID, client_secret: env.RAFT_CLIENT_SECRET });
    const response = await fetch(tokenUrl, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return error(response.status === 400 ? 400 : 502, response.status === 400 ? "invalid_code" : "exchange_failed", response.status === 400 ? "The authorization code is invalid or expired; run Raft login again." : "Raft could not complete the login exchange.");
    token = await response.json() as typeof token;
    if (!token.access_token) throw new Error("missing access token");
  } catch {
    return error(502, "exchange_failed", "Raft could not complete the login exchange.");
  }

  try {
    const authHeaders = { Authorization: `Bearer ${token.access_token}`, Accept: "application/json" };
    const [userResponse, serverResponse] = await Promise.all([
      fetch("https://api.raft.build/api/oauth/userinfo", { headers: authHeaders, redirect: "manual", signal: AbortSignal.timeout(10_000) }),
      fetch("https://api.raft.build/api/oauth/serverinfo", { headers: authHeaders, redirect: "manual", signal: AbortSignal.timeout(10_000) }),
    ]);
    if (!userResponse.ok || !serverResponse.ok) return error(502, "exchange_failed", "Raft identity could not be verified.");
    const user = await userResponse.json() as Record<string, unknown>;
    const server = await serverResponse.json() as Record<string, unknown>;
    const scopes = (token.scope ?? "").split(/[\s,]+/).filter(Boolean);
    if (!scopes.includes("openid") || !scopes.includes("profile")) return error(403, "not_authorized", "The Raft grant must include openid and profile scopes.");
    const principalId = user.sub ?? user.id;
    const serverId = server.id ?? server.server_id;
    const serverSlug = server.slug;
    if (!serverId || !serverSlug) return error(403, "server_context_missing", "This login has no Raft server context.");
    if (!principalId) return error(502, "exchange_failed", "Raft did not return a principal identity.");
    const blocked = await env.DB.prepare("SELECT 1 FROM blocked_servers WHERE server_id = ?").bind(String(serverId)).first();
    if (blocked) return error(403, "server_blocked", "This Raft server is blocked from using Claim Check.");

    const id = randomId();
    const idHash = await hmac(env.SESSION_SECRET, id);
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + SESSION_SECONDS * 1000).toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE server_id = ? AND principal_id = ? AND revoked_at IS NULL").bind(createdAt.toISOString(), String(serverId), String(principalId)),
      env.DB.prepare("INSERT INTO sessions (id_hash, server_id, server_slug, server_name, principal_id, principal_type, display_name, scopes, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, 'agent', ?, ?, ?, ?, NULL)").bind(idHash, String(serverId), String(serverSlug), typeof server.name === "string" ? server.name : String(serverSlug), String(principalId), typeof user.name === "string" ? user.name : typeof user.preferred_username === "string" ? user.preferred_username : null, scopes.join(" "), createdAt.toISOString(), expiresAt),
    ]);
    const headers = new Headers();
    headers.append("Set-Cookie", `${SESSION_COOKIE}=${id}; HttpOnly; Secure; SameSite=Strict; Path=/api/agent; Max-Age=${SESSION_SECONDS}`);
    return json({ status: "session_created", session_expires_at: expiresAt }, 200, headers);
  } catch {
    return error(502, "exchange_failed", "Raft identity could not be verified.");
  }
}

function cookieValue(request: Request): string | null {
  const value = request.headers.get("Cookie")?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  return value ? value.slice(SESSION_COOKIE.length + 1) : null;
}

async function authenticate(request: Request, env: Env): Promise<{ session?: Session; response?: Response }> {
  const rawId = cookieValue(request);
  if (!rawId || !/^[a-f0-9]{64}$/.test(rawId) || !env.SESSION_SECRET) return { response: error(401, "not_authenticated", "Run raft integration login to create a Claim Check session.") };
  const idHash = await hmac(env.SESSION_SECRET, rawId);
  const session = await env.DB.prepare("SELECT id_hash, server_id, server_slug, server_name, principal_id, principal_type, display_name, scopes, expires_at FROM sessions WHERE id_hash = ? AND expires_at > ? AND revoked_at IS NULL").bind(idHash, nowIso()).first<Session>();
  if (!session || !session.scopes.split(" ").includes("openid") || !session.scopes.split(" ").includes("profile")) return { response: error(401, "not_authenticated", "Run raft integration login to create a Claim Check session.") };
  const blocked = await env.DB.prepare("SELECT 1 FROM blocked_servers WHERE server_id = ?").bind(session.server_id).first();
  if (blocked) return { response: error(403, "not_authorized", "This Raft server is not authorized to use Claim Check.") };
  return { session };
}

// v1 actions parse leniently, exactly as request.json() did: UTF-8 with replacement, BOM stripped, JSON.parse.
function lenientJsonObject(body: Uint8Array): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(body));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

const getSession: ActionHandler = async (ctx, body) => {
  if (!lenientJsonObject(body)) return error(400, "invalid_request", "The request body must be a JSON object.");
  const limited = await reserve(ctx.store, "read", ctx.session, ctx.now);
  if (limited) return limited;
  const { session } = ctx;
  return json({ principal: { id: session.principal_id, type: session.principal_type, display_name: session.display_name }, server: { id: session.server_id, slug: session.server_slug, name: session.server_name }, session_expires_at: session.expires_at });
};

const getReceipt = (db: D1Database): ActionHandler => async (ctx, body) => {
  const request = lenientJsonObject(body);
  if (!request) return error(400, "invalid_request", "The request body must be a JSON object.");
  // The design intentionally maps malformed and absent IDs to the same 404 as
  // unknown, expired, deleted, and other-server receipts.
  const limited = await reserve(ctx.store, "read", ctx.session, ctx.now);
  if (limited) return limited;
  const id = typeof request.receipt_id === "string" ? request.receipt_id : "";
  const receipt = await db.prepare("SELECT body_json FROM receipts WHERE id = ? AND server_id = ? AND expires_at > ?").bind(id, ctx.session.server_id, nowIso()).first<{ body_json: string }>();
  if (!receipt) return error(404, "receipt_not_found", "No accessible, unexpired receipt has that ID.");
  return new Response(receipt.body_json, { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
};

async function purge(env: Env): Promise<void> {
  const now = new Date();
  const sessionCutoff = new Date(now.getTime() - 7 * 86_400_000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM receipts WHERE expires_at <= ?").bind(now.toISOString()),
    env.DB.prepare("DELETE FROM sessions WHERE (expires_at <= ? OR revoked_at <= ?) AND COALESCE(revoked_at, expires_at) <= ?").bind(sessionCutoff, sessionCutoff, sessionCutoff),
    env.DB.prepare("DELETE FROM rate_reservations WHERE created_at <= ?").bind(now.getTime() - 3_600_000),
  ]);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== canonicalOrigin(env)) return error(404, "not_found", "No route matches this request.");
    if (url.pathname === MANIFEST_PATH && request.method === "GET") return json(manifest);
    if (url.pathname === CALLBACK_PATH && request.method === "GET") return callback(request, env);
    const routes: Record<string, ActionHandler> = {
      "/api/agent/actions/get-session": getSession,
      "/api/agent/actions/get-receipt": getReceipt(env.DB),
      "/api/agent/actions/register-key": registerKey,
      "/api/agent/actions/submit-receipt": submitReceipt,
      "/api/agent/actions/list-keys": listKeys,
      "/api/agent/actions/revoke-key": revokeKey,
    };
    const route = routes[url.pathname];
    if (route && request.method === "POST") {
      try {
        // Verification step 1 runs before the session check: an oversize body is refused without a cookie lookup.
        const body = await readBody(request);
        if (!body) {
          return route === submitReceipt
            ? error(413, "receipt_too_large", "The request body exceeds 64 KB.")
            : error(400, "invalid_request", "Request body exceeds 64 KB.");
        }
        const auth = await authenticate(request, env);
        if (!auth.session) return auth.response!;
        return await route({ store: new D1Store(env.DB), session: auth.session, now: Date.now() }, body);
      } catch {
        return error(500, "internal_error", "The request could not be completed.");
      }
    }
    return error(404, "not_found", "No route matches this request.");
  },
  async scheduled(_event: ScheduledController, env: Env): Promise<void> { await purge(env); },
};
