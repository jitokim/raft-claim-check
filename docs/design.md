# Claim Check: Phase 1 design

Claim Check is a Raft Connected App, hosted on Cloudflare Workers, that any Raft server can install. An agent sends a structured claim (for example "PR #312 in acme/widgets is merged"). Claim Check checks it **read-only** against its source of truth, which in v1 means the public GitHub REST API. It returns a receipt with one verdict per claim: **confirmed ✅**, **contradicted ❌**, or **can't check ⚠️**. Each verdict comes with the time of the read, the exact endpoint read, what the read proves and does not prove, and which facts were verified and which were inferred. Claim Check never executes anyone's code and never writes to GitHub. It turns the proof-of-work receipt recipe (Raft Manual recipe `proof-of-work-receipts`) into a product.

This document covers design only. The manifest draft is `docs/manifest.draft.json`. Every origin below is a placeholder (see [Hosting](#hosting)).

**Manifest schema string: `"raft-agent-manifest.v0"`.** Both prefixes are live today. Raft Artifacts (raft-artifacts.com) serves `slock-agent-manifest.v0`, and tdoc (tdoc.dev) serves `raft-agent-manifest.v0`. tdoc is listed on the Raft Marketplace with the `raft-` string, so Raft's parser accepts it, and v1 uses the current brand name. **Rejected:** copying the `slock-` string from the Raft Artifacts example. `slock` is the older name (the Raft Manual, `integration` topic, says the "former `slock_builtin` Connected App class is retired"), and nothing says new manifests should use it.

## Actions

**Decision:** v1 has three manifest actions: `check_claims`, `get_receipt`, and `get_session`. All three are `POST` under `/api/agent/actions/`, require the service session cookie, and return JSON. Claims are **structured objects** with a `kind` discriminator and typed fields. Claim Check never interprets free text. **Rejected:** a free-text claim parsed by a model. A model can misread a claim and then check the wrong thing, and a receipt for the wrong thing is the proxy-receipt failure that the Raft Manual recipe `proof-of-work-receipts` warns about.

### Claim kinds understood by v1

Every claim needs `kind`, `owner`, and `repo`. It may also carry `statement`, a free-text string of at most 500 characters. Claim Check stores and echoes `statement` verbatim and **never parses it**. Field formats:
- `owner`/`repo`: GitHub name characters only.
- `number`: a positive integer.
- `sha`: a full 40-character hex SHA. A short SHA is rejected because it can be ambiguous.
- `branch`/`tag`: a git ref name, sent to GitHub percent-encoded.

| `kind` | Extra typed fields | Acceptance surface read (GitHub REST, all `GET`) |
| --- | --- | --- |
| `pr_merged` | `number` | `/repos/{owner}/{repo}/pulls/{number}` → `merged`, `merged_at`, `merge_commit_sha`, `base.ref` |
| `pr_state` | `number`, `expected_state`: `open` \| `closed_unmerged` \| `merged` | `/repos/{owner}/{repo}/pulls/{number}` → `state`, `merged` |
| `ci_status` | `sha`, `expected_conclusion`: `success` \| `failure`, optional `check_names` (array of strings) | `/repos/{owner}/{repo}/commits/{sha}/check-runs` (latest per check, paginated, max 3 pages of 100) and `/repos/{owner}/{repo}/commits/{sha}/status` |
| `commit_on_branch` | `sha`, `branch` | `/repos/{owner}/{repo}/branches/{branch}`, then `/repos/{owner}/{repo}/compare/{branch}...{sha}` → `status` |
| `issue_closed` | `number` | `/repos/{owner}/{repo}/issues/{number}` → `state`, `state_reason`, `closed_at`, presence of `pull_request` |
| `tag_exists` | `tag`, optional `sha` | `/repos/{owner}/{repo}/git/ref/tags/{tag}` (singular `ref`, which matches the exact name; the plural `refs` does prefix matching). If `sha` is given and the ref points at an annotated tag object, Claim Check also reads `/repos/{owner}/{repo}/git/tags/{object_sha}` to peel it. |
| `release_published` | `tag` | `/repos/{owner}/{repo}/releases/tags/{tag}` → `draft`, `prerelease`, `published_at` |

Verdict rules, applied after the repo gate described in [GitHub access](#github-access):
- `pr_merged`: `merged == true` → ✅. Otherwise → ❌. A PR number that returns 404 on a readable public repo → ❌.
- `pr_state`: the observed state is exactly one of `open`, `closed_unmerged`, or `merged`. ✅ if it equals `expected_state`, otherwise ❌.
- `ci_status` with `expected_conclusion: success`:
  - ✅ requires all of the following. There is at least one check run or commit status. Every check run in scope is `completed` with a conclusion of `success`, `neutral`, or `skipped`. The combined status is `success`, or there are zero statuses.
  - Any failing conclusion → ❌.
  - Any check still queued or in progress → ❌, recorded as `ci_not_concluded`. The claim "CI is green" is about the moment of the read, and a pending check is a fact we read, not missing evidence.
  - Zero checks → ⚠️ `no_ci_found`, because the absence of CI is not green CI.
  - A name in `check_names` with no matching run → ⚠️ `check_not_found`.
  - More than 300 runs → ⚠️ `too_many_checks`.
  - `expected_conclusion: failure` → ✅ if at least one in-scope run or status has failed, ❌ if all have concluded green.
- `ci_status` with `expected_conclusion: failure`, the remaining cases:
  - Every check is pending, queued, or in progress, and none has failed → ❌ `ci_not_concluded`. As on the success side, the claim is about the moment of the read, and at that moment nothing had failed. A failure that has already been recorded is final for that run, so a failed run next to pending ones still gives ✅.
  - Zero checks and zero statuses → ⚠️ `no_ci_found`, the same as on the success side. With no CI, there is nothing that could have failed.
  - A check-run `status`, check-run `conclusion`, or commit-status `state` that Claim Check does not recognise → ⚠️, with `unknown_check_status`, `unknown_check_conclusion`, or `unknown_status_state`. This applies to both `expected_conclusion` values. A new GitHub value is never treated as green or as failed.
- `ci_status` precedence when several values are in scope, for either `expected_conclusion`. The first matching step decides:
  1. ⚠️ `too_many_checks`, `check_not_found`, or any unknown value.
  2. ⚠️ `no_ci_found`.
  3. Success: any failed value → ❌ `ci_failed`. Then any cancelled, action-required, or stale run → ❌ `ci_not_green`. Then any pending value → ❌ `ci_not_concluded`. Otherwise → ✅.
  4. Failure: any failed value → ✅. Then any cancelled, action-required, or stale run → ⚠️ `ci_ambiguous_conclusion`. Such a run is neither green nor a failure, so Claim Check does not decide whether it counts as "CI failed". Then any pending value → ❌ `ci_not_concluded`. Otherwise every item is green → ❌ `ci_all_green`.
- `commit_on_branch`: Claim Check compares the branch with the SHA. A compare `status` of `identical` or `behind` (the SHA is an ancestor of the branch head) → ✅. A status of `ahead` or `diverged` → ❌. A branch that returns 404 on a readable public repo → ❌. A SHA that returns 404 or 422 → ❌ `commit_not_found`.
- `issue_closed`: `state == closed` → ✅, and `state_reason` is reported but not judged. `state == open` → ❌. If the response has a `pull_request` key → ⚠️ `wrong_kind` (use `pr_state`). A 301 (the issue was transferred) → ⚠️ `issue_moved`, recording the `Location` without following it. A 410 → ⚠️ `issue_deleted`.
- `tag_exists`: a 200 → ✅. If `sha` was given, the peeled target must equal it, otherwise ❌. A 404 → ❌.
- `release_published`: a 200 with `draft == false` → ✅, with `prerelease` reported. A 404 → ❌. Our public-only token cannot see drafts, so a draft also reads as 404, and the claim "published" is false either way.
- Any other `kind`, or a known kind missing a required field, → ⚠️ `unsupported_claim_kind` or `invalid_claim`. Claim Check never guesses.

The table below shows the `ci_status` verdict each GitHub value produces. Check runs are read as the latest run per check name. Commit statuses are read from the per-context `statuses[]` of `/commits/{sha}/status`, which is the latest status per context. A green row produces its verdict only when every in-scope item is green.

| Source | Value | Class | `expected_conclusion: success` | `expected_conclusion: failure` |
| --- | --- | --- | --- | --- |
| check-run `conclusion` | `success` | green | ✅ | ❌ `ci_all_green` |
| check-run `conclusion` | `neutral` | green | ✅ | ❌ `ci_all_green` |
| check-run `conclusion` | `skipped` | green | ✅ | ❌ `ci_all_green` |
| check-run `conclusion` | `failure` | failed | ❌ `ci_failed` | ✅ |
| check-run `conclusion` | `timed_out` | failed | ❌ `ci_failed` | ✅ |
| check-run `conclusion` | `startup_failure` | failed | ❌ `ci_failed` | ✅ |
| check-run `conclusion` | `cancelled` | not green, not failed | ❌ `ci_not_green` | ⚠️ `ci_ambiguous_conclusion` |
| check-run `conclusion` | `action_required` | not green, not failed | ❌ `ci_not_green` | ⚠️ `ci_ambiguous_conclusion` |
| check-run `conclusion` | `stale` | not green, not failed | ❌ `ci_not_green` | ⚠️ `ci_ambiguous_conclusion` |
| check-run `conclusion` | any other value | unknown | ⚠️ `unknown_check_conclusion` | ⚠️ `unknown_check_conclusion` |
| check-run `status` (not `completed`) | `queued`, `in_progress`, `waiting`, `requested`, `pending` | pending | ❌ `ci_not_concluded` | ❌ `ci_not_concluded` |
| check-run `status` | any other value | unknown | ⚠️ `unknown_check_status` | ⚠️ `unknown_check_status` |
| commit-status `state` | `success` | green | ✅ | ❌ `ci_all_green` |
| commit-status `state` | `failure` | failed | ❌ `ci_failed` | ✅ |
| commit-status `state` | `error` | failed | ❌ `ci_failed` | ✅ |
| commit-status `state` | `pending` | pending | ❌ `ci_not_concluded` | ❌ `ci_not_concluded` |
| commit-status `state` | any other value | unknown | ⚠️ `unknown_status_state` | ⚠️ `unknown_status_state` |
| (none) | no check runs and no statuses | none | ⚠️ `no_ci_found` | ⚠️ `no_ci_found` |

### `check_claims`

`POST /api/agent/actions/check-claims`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `claims` | object | yes | The request body is an object whose `claims` field is a non-empty array of 1–20 structured claims, as described above. Order is preserved in the results. |

The manifest declares `claims` as type `"object"`, because the live manifests only use the parameter types `string`, `number`, `boolean`, and `object`. The claim list is carried inside the request body, and agents pass that body with `raft integration invoke ... --data-json`. The request body looks like this:

```json
{
  "claims": [
    { "kind": "pr_merged", "owner": "acme", "repo": "widgets", "number": 312, "statement": "PR #312 is merged" }
  ]
}
```

Response `200`. A receipt is stored and returned even when some or all verdicts are ⚠️:

```json
{
  "receipt_id": "rcpt_EXAMPLEONLY0000000000000000",
  "created_at": "2026-10-06T09:00:03Z",
  "expires_at": "2027-01-04T09:00:03Z",
  "server": { "id": "srv_example", "slug": "example" },
  "requested_by": { "principal_id": "agent_example", "principal_type": "agent" },
  "summary": { "confirmed": 1, "contradicted": 0, "cant_check": 0 },
  "results": [
    {
      "index": 0,
      "claim": { "kind": "pr_merged", "owner": "acme", "repo": "widgets", "number": 312, "statement": "PR #312 is merged" },
      "verdict": "confirmed",
      "symbol": "✅",
      "reason": null,
      "retry_after_seconds": null,
      "checked_at": "2026-10-06T09:00:02Z",
      "source": {
        "system": "github",
        "reads": [
          { "method": "GET", "endpoint": "/repos/acme/widgets", "status": 200 },
          { "method": "GET", "endpoint": "/repos/acme/widgets/pulls/312", "status": 200 }
        ]
      },
      "acceptance_surface": "GitHub pull request acme/widgets#312, field merged",
      "proved": ["At checked_at, GitHub reported PR #312 as merged into main"],
      "not_proved": ["That CI passed on the merge commit", "That the change is deployed"],
      "verified": [
        { "fact": "merged", "value": true, "from": "/repos/acme/widgets/pulls/312#merged" },
        { "fact": "merge_commit_sha", "value": "<40-hex sha as read>", "from": "/repos/acme/widgets/pulls/312#merge_commit_sha" }
      ],
      "inferred": []
    }
  ]
}
```

- `expires_at` is `created_at` + 90 days. It is part of the receipt body from creation, so `check_claims` and `get_receipt` return the same value.
- `verdict` is one of `confirmed`, `contradicted`, or `cant_check`. `symbol` is ✅, ❌, or ⚠️. `reason` is a stable code, always set for ❌ and ⚠️. `retry_after_seconds` is set only when retrying could change a ⚠️.
- `verified` holds field values copied verbatim from a source response, each with the endpoint and field it came from. `inferred` holds every statement Claim Check derived by combining or interpreting fields, each with its rule. For example: "SHA is reachable from branch, inferred from compare status `behind`."
- `source.reads` lists every read that contributed to the verdict, in order. It records the endpoint path and HTTP status, never request headers or the token.

Errors return `{ "error": "<code>", "hint": "<one sentence>" }`, which is the shape the Raft CLI surfaces (Raft Manual, `integration` topic):
- `400 invalid_request`: the body is not an object, `claims` is missing, or the list inside it is not an array, is empty, or has more than 20 items. A `400` is returned before the rate-limit reservation, so it consumes no budget and makes no GitHub read. A malformed *individual* claim does not fail the request. That claim gets ⚠️ `invalid_claim` or `unsupported_claim_kind`.
- `401 not_authenticated`: the session is missing, expired, or revoked. The fix is to re-run `raft integration login`.
- `403 not_authorized`: the server is blocked, or the session has no server context.
- `429 rate_limited`: the request exceeds a Claim Check limit. The response includes `Retry-After`, and no receipt is created.
- `500 internal_error`: no receipt is created. Claim Check never returns partial results without a stored receipt.

### `get_receipt`

`POST /api/agent/actions/get-receipt`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt_id` | string | yes | The `receipt_id` returned by `check_claims`. |

Response `200`: the stored receipt, exactly the body `check_claims` returned, including its `expires_at`, which is part of the stored body from the start. Retrieval adds no field. A stored receipt is immutable and is never re-checked. To re-check, call `check_claims` again, which creates a new receipt.

Errors: `401 not_authenticated`. `404 receipt_not_found` covers every one of these cases with the identical body: an unknown ID, a malformed ID, an expired or deleted receipt, and a receipt owned by another server. `429 rate_limited`.

### `get_session`

`POST /api/agent/actions/get-session`. It takes no parameters. This is the documented read-only check an agent runs after `raft integration login` to confirm the service session really works (the Raft Manual, `integration` topic, says a stored cookie is "unverified" until such a check passes).

Response `200`:
`{ "principal": { "id", "type", "display_name" }, "server": { "id", "slug", "name" }, "session_expires_at" }`.

Errors: `401 not_authenticated`, `403 not_authorized`.

## Login with Raft

**Decision:** the callback path is exactly `/auth/agent/callback`, and the full callback URL is the constant `CALLBACK_URL = CANONICAL_ORIGIN + "/auth/agent/callback"`. The Worker never builds it from the `Host` header, `X-Forwarded-*`, or the request URL. The callback mints Claim Check's own opaque service session cookie, with a path that covers every action endpoint. **Rejected:** a stateless signed cookie such as a JWT. It cannot be revoked before it expires, and revocation is a lifecycle requirement (https://docs.raft.build/features/apps/login-with-raft/, https://docs.raft.build/developers/login-with-raft/).

Registration uses the agent flow from https://docs.raft.build/developers/login-with-raft/. It runs `raft integration app prepare register` with `--redirect-url` set to the exact `CALLBACK_URL` and the scopes `openid` and `profile`, and passes the manifest URL (`CANONICAL_ORIGIN + "/.well-known/raft-agent-manifest.json"`) explicitly. A human commits the card.

**Credential boundary.** Following the Raft Artifacts example, the manifest declares a top-level `"credential_boundary": {"storage": "slock_managed_token"}` alongside `auth` and its `login_url`. Its exact effect is confirmed at preflight (see [Open questions](#open-questions)).

**Callback (`GET /auth/agent/callback`).** The callback runs these steps in order:
1. Read the one-time `code`. The agent CLI handoff does not run a relying-party state/PKCE flow (Raft Manual, `integration` topic), so v1 serves agent principals only. Human browser login, which would need `state`/PKCE, is planned for v1.1.
2. Exchange the code once at the token endpoint. The endpoint comes from `https://api.raft.build/.well-known/openid-configuration`. The exchange sends `redirect_uri = CALLBACK_URL`, the client ID, and the client secret, and leaves out `code_verifier`. There is no retry and no replay of the code.
3. Call `GET /api/oauth/userinfo` and `GET /api/oauth/serverinfo` with the access token.
4. Fail closed if the server context is missing (`403 server_context_missing`) or the server is blocked (`403 server_blocked`). A failed exchange returns `400 invalid_code` or `502 exchange_failed`. Every error body is `{error, hint}`.
5. Discard the access token and the code. Claim Check stores no Raft tokens, and the exchange issues no refresh token.
6. Mint the session:
   - Generate 256 random bits as the session ID.
   - Store `HMAC-SHA256(SESSION_SECRET, id)` in D1, never the raw ID.
   - Revoke any earlier active session for the same principal and server.
   - Respond `200 {"status":"session_created","session_expires_at":...}` with the cookie set.

**Cookie:** `cc_session=<id>; HttpOnly; Secure; SameSite=Strict; Path=/api/agent; Max-Age=86400`. It has no `Domain` attribute, so it is host-only on the canonical origin. `Path=/api/agent` covers all three action paths. The cookie's scope is the one principal and the one token-bound server. It grants only the v1 actions and nothing else.

**Lifecycle.** The session has an absolute 24-hour expiry with no sliding renewal. It is revoked in three cases:
- A new login for the same principal and server revokes the previous session.
- An operator can revoke a session, all sessions for a principal, or all sessions for a server.
- Blocking a server revokes its sessions.

When a server uninstalls Claim Check, v1 relies on the 24-hour session expiry. Whether Raft sends an uninstall notification, which would let Claim Check revoke that server's sessions at once, is checked later (see [Open questions](#open-questions)).

An expired or revoked session gets `401 not_authenticated`, and the fix is to re-run `raft integration login`. The fix is never a workaround. Because Claim Check keeps no Raft token, it cannot re-check membership mid-session. The 24-hour cap bounds that window.

**Request to server mapping (identity is not authorization).** Each action request resolves cookie → hashed ID → `sessions` row → `server_id`. The server comes **only** from the session, which comes from the token-bound `serverinfo`. Any server field in the body or headers is ignored. Access is allowed only if every layer passes:
- **Granted scopes:** `openid` and `profile` are present.
- **Server binding:** the token was issued for this server's installation, and the server is not in `blocked_servers`.
- **App-local policy:** in v1, any principal of an installed server may call `check_claims` and may read that server's receipts. Per-server allowlists of agents may come later.

If any layer fails, the request fails closed with the generic `401` or `403`.

## GitHub access

**Decision:** v1 reads GitHub **with a token** (the `GITHUB_TOKEN` secret). The token is a fine-grained token restricted to **public repositories, read-only**, so Claim Check checks public repos only. **Rejected:** unauthenticated reads. The limit is per egress IP, and Workers share egress IPs with other tenants, so Claim Check could be rate-limited by traffic it does not control. **Also rejected:** a token with private-repo access. It is shared by every installing server, so any server could read the state of a private repo it has no right to see.

**Token owner:** `GITHUB_TOKEN` is a fine-grained personal access token on the project owner's GitHub account, read-only on public repositories. It is stored only as the Worker secret `GITHUB_TOKEN`, never in the repo, chat, or docs.

GitHub limits we rely on. **NEEDS RE-VERIFICATION against GitHub's current docs before implementation** (see [Open questions](#open-questions)):
- Unauthenticated: 60 requests/hour per IP.
- Authenticated with a personal token: 5,000 requests/hour per account.
- Secondary (abuse) limits exist and may return `403` or `429` with `Retry-After`.
- Remaining budget is reported in `x-ratelimit-remaining` and `x-ratelimit-reset`.

A claim costs 2–5 reads. Claim Check reads the repo once per request per `owner/repo`, so claims on the same repo share that read. At about 3 reads per claim, the 5,000/hour budget covers about 1,600 claims/hour across all servers. That number sets the limits in [Rate limits and abuse](#rate-limits-and-abuse).

**Repo gate.** Every claim first needs `GET /repos/{owner}/{repo}` to return `200` with `private == false`. Otherwise:
- `404` → ⚠️ `repo_not_readable`. GitHub returns 404 for a private repo the caller cannot see and also for a repo that does not exist, so **a 404 does not prove absence**. Returning ❌ would claim something we did not observe.
- `301` (renamed or transferred) → ⚠️ `repo_moved`, recording `Location` without following it.
- `451` → ⚠️ `repo_unavailable`.
- `403` or `429` caused by rate limiting → ⚠️ `github_rate_limited`.
- `5xx` or a timeout after 10 seconds → ⚠️ `source_unavailable`.

Only after this gate passes may a 404 on a *sub-resource* (a PR number, branch, tag, or release) count as evidence of absence and produce ❌. The repo is known to be public and readable at that point, so the 404 is no longer ambiguous.

## Storage

**Decision:** a single **D1** database holds receipts, sessions, rate-limit reservations, and the server block list. **Rejected:** KV. It is eventually consistent, so a revoked session or an exhausted rate window can stay valid on another edge for up to about a minute. It also cannot run the `id AND server_id` lookup as one indexed query. **Also rejected:** no storage at all, because `get_receipt` and revocation both need state.

```
receipts(
  id            TEXT PRIMARY KEY,      -- "rcpt_" + 26 chars base32 of 128 random bits
  server_id     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  principal_type TEXT NOT NULL,        -- "agent" in v1
  created_at    TEXT NOT NULL,         -- RFC 3339 UTC
  expires_at    TEXT NOT NULL,         -- created_at + 90 days; same value as body_json's expires_at
  confirmed     INTEGER NOT NULL,
  contradicted  INTEGER NOT NULL,
  cant_check    INTEGER NOT NULL,
  body_json     TEXT NOT NULL          -- the exact check_claims response body, including expires_at
)
INDEX receipts_server_created (server_id, created_at)
INDEX receipts_expires (expires_at)

sessions(
  id_hash       TEXT PRIMARY KEY,      -- HMAC-SHA256(SESSION_SECRET, session id)
  server_id     TEXT NOT NULL,
  server_slug   TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  principal_type TEXT NOT NULL,
  display_name  TEXT,
  scopes        TEXT NOT NULL,         -- space-separated granted scopes
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,         -- created_at + 24 h
  revoked_at    TEXT
)
INDEX sessions_principal (server_id, principal_id)

rate_reservations(
  id            INTEGER PRIMARY KEY,
  server_id     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  action        TEXT NOT NULL,         -- "check_claims" or "read" (get_receipt, get_session)
  claim_count   INTEGER NOT NULL,      -- submitted claim count; 0 for "read"
  created_at    INTEGER NOT NULL       -- Unix milliseconds
)
INDEX rate_principal (server_id, principal_id, action, created_at)
INDEX rate_server (server_id, action, created_at)

blocked_servers(
  server_id     TEXT PRIMARY KEY,
  blocked_at    TEXT NOT NULL,
  reason        TEXT NOT NULL
)
```

`body_json` holds only extracted fields and endpoint paths. It never holds raw GitHub response bodies, request headers, or any token. **Retention:**
- Receipts: 90 days, then hard-deleted. After that, `get_receipt` returns the same 404 as for an unknown ID.
- Sessions: rows are deleted 7 days after `expires_at` or `revoked_at`, whichever comes first.
- Rate reservations: deleted once they are older than one hour, the longest window.

A daily scheduled purge does the deletion.

## Receipt visibility

**Decision:** a receipt is visible only to principals of the **Raft server that requested it**. Any agent on that server may read it, so a receipt can be handed off within the server, and no other server can. `get_receipt` runs exactly one query: `SELECT … WHERE id = ? AND server_id = ? AND expires_at > now`. The `server_id` comes from the session. When that query returns no row, the response is the identical `404 receipt_not_found` body, whether the ID is unknown, malformed, expired, or owned by another server. Nothing reveals that a receipt exists elsewhere. **Rejected:** public share URLs. A public link would turn a receipt into a bearer credential and leak a private server's activity, which cuts against Raft's members-only defaults.

A receipt has a **stable ID but no URL** in v1. Agents cite `receipt_id` in handoffs, and a reader on the same server fetches the receipt with `get_receipt`. A member-only HTML receipt page that requires human login is planned for v1.1, not v1.

## Rate limits and abuse

**Decision:** Claim Check enforces sliding-window limits in D1 and reserves capacity **before** any GitHub read. These values are accepted for v1:

| Limit | Value |
| --- | --- |
| Claims per `check_claims` request | max **20** |
| `check_claims` requests per agent | **6 / minute** |
| Claims per agent | **100 / hour** |
| Claims per server (all its principals) | **300 / hour** |
| `get_receipt` + `get_session` per agent | **120 / minute** |
| Global GitHub reserve | stop new checks while `x-ratelimit-remaining < 500` |

**Atomic reservation.** After authentication and the request-level `400` checks, and before any GitHub read, `check_claims` makes one conditional reservation. It is a single D1 statement. It inserts one `rate_reservations` row only if the per-agent request count, the per-agent claim count, and the per-server claim count all stay within their caps once this request is added. `:n` is the number of submitted claims.

```sql
INSERT INTO rate_reservations (server_id, principal_id, action, claim_count, created_at)
SELECT :server_id, :principal_id, 'check_claims', :n, :now
WHERE (SELECT COUNT(*) FROM rate_reservations
        WHERE server_id = :server_id AND principal_id = :principal_id
          AND action = 'check_claims' AND created_at > :now - 60000) < 6
  AND (SELECT COALESCE(SUM(claim_count), 0) FROM rate_reservations
        WHERE server_id = :server_id AND principal_id = :principal_id
          AND action = 'check_claims' AND created_at > :now - 3600000) + :n <= 100
  AND (SELECT COALESCE(SUM(claim_count), 0) FROM rate_reservations
        WHERE server_id = :server_id
          AND action = 'check_claims' AND created_at > :now - 3600000) + :n <= 300;
```

The reservation succeeded only if `meta.changes = 1`. If `meta.changes = 0`, the response is `429 rate_limited`, nothing is recorded, and `Retry-After` comes from the oldest reservation still inside the exhausted window. Two simultaneous requests cannot both pass on the same remaining capacity. A single SQLite write statement is atomic: its count subqueries and its insert run under one write lock. D1 also serialises writes to a database. So the second statement always runs after the first has committed, sees the first row in its subqueries, and fails if that row used up the capacity. `get_receipt` and `get_session` use the same shape with `action = 'read'`, `claim_count = 0`, and the single condition `COUNT(*) < 120` over the last 60 seconds. The global GitHub reserve is checked before the reservation, so a request refused by the reserve consumes no budget.

- **Malformed or unsupported claims count toward the claim budget.** The reservation is made on the submitted claim count, before per-claim validation. If invalid claims were free, an agent could probe the validator or pad requests at no cost. Counting every submitted claim keeps the budget simple and stops cheap probing.
- **A failed request is not refunded.** If a request fails with `500` after the reservation but before a receipt is stored, the reservation stays consumed. GitHub reads may already have been spent on it, and a refund write could itself fail and leave the counts inconsistent.

If any of these limits is exceeded, the response is `429 rate_limited` with `Retry-After` and **no receipt**. The global reserve keeps one server from draining the shared token budget. **Rejected:** caching GitHub responses to save budget. A cached read would give a stale verdict with a fresh `checked_at`, which is exactly the false receipt this product exists to prevent.

**When GitHub's own limit is hit mid-request**, the claims already read keep their real verdicts. Every remaining claim gets ⚠️ `github_rate_limited` with `retry_after_seconds`, taken from `Retry-After` or `x-ratelimit-reset`. The request still returns `200` with a stored receipt. Claim Check never substitutes a stale, cached, or guessed verdict.

Abuse controls:
- Requests are capped at 64 KB.
- Each GitHub read times out after 10 seconds.
- Redirects are never followed.
- Claim Check reads only `api.github.com` paths built from validated typed fields, so a claim cannot make Claim Check fetch an arbitrary URL.
- An operator can add a server to `blocked_servers`.

## What a receipt proves and does not prove

**Decision:** each result names its **acceptance surface**, which is the exact GitHub object and field the claim is about. It then states `proved` and `not_proved` and separates `verified` (values read verbatim, with endpoint and field) from `inferred` (conclusions, with the rule), following the Raft Manual recipe `proof-of-work-receipts`. Claim Check checks **only the surface the claim names** and never a nearby proxy. **Rejected:** a single "looks good" boolean, because it is the "unscoped receipt" failure in the Raft Manual recipe `proof-of-work-receipts`, where a reader takes the receipt to prove more than it does.

Every receipt proves only what GitHub's API reported **at `checked_at`**, from the listed reads. It does not prove the state before or after that time. Force-pushes, re-runs, reopened PRs, and deleted tags can all change the answer later. It does not prove anything about systems other than GitHub, and it does not prove that the agent did the work.

The proxy trap, and how v1 avoids it:
- **Green check on the PR head SHA ≠ CI green on the merge commit.** `ci_status` checks exactly the `sha` given and never swaps in another. To claim "merged and CI green", an agent sends `pr_merged` plus `ci_status` on the `merge_commit_sha` that the `pr_merged` result lists under `verified`. A green head SHA leaves "CI on the merge commit" in `not_proved`.
- **A "closed" PR ≠ a merged PR.** GitHub's `state` is `closed` for both. `pr_merged` reads `merged`, and `pr_state` keeps `closed_unmerged` and `merged` distinct.
- **A tag existing ≠ a release being published.** `tag_exists` proves only the git ref. `release_published` reads the release object and its `draft` flag. Neither proves that release assets were uploaded or are correct.
- **Green check runs ≠ all required checks passed.** v1 cannot read branch protection rules, because that needs admin permissions, so "required checks" is always in `not_proved`.
- **A commit on a branch ≠ merged through review, and ≠ deployed.** `commit_on_branch` proves ancestry only.
- **An issue closed ≠ the issue fixed.** `state_reason` is reported under `verified`, but whether the issue was fixed stays in `not_proved`.

## oh-my-graph runs as evidence

**Decision:** v1 does **not** support oh-my-graph runs. Run logs live on the operator's machine under `~/.oh-my-graph/runs/`, and a Worker cannot read that machine. A claim of this kind gets ⚠️ `unsupported_claim_kind`. **Rejected:** accepting a log the agent uploads alongside its claim. The claimant would be supplying its own evidence, which is self-attestation and not a check.

A later version would need these pieces:
- **An operator-side publisher.** A small process the operator runs, not the agent, pushes a digest of each completed run to Claim Check automatically when the run finishes. The digest covers run ID, start and end times, exit status, and a hash of the log. The upload never happens on demand at claim time, so the evidence is on record before the claim is made.
- **A signature with an operator-held key.** Each server registers the public key with Claim Check. The private key sits outside the agent's runtime and environment, so the agent cannot sign its own evidence.
- **Honest labelling.** Run evidence would appear under `inferred` as "operator-attested", never under `verified`. A receipt would also say plainly that it proves only what the operator's machine reported.
- **A preference for corroboration.** Where a run references a commit or PR, Claim Check would check that reference against GitHub independently.

## Hosting

**Decision:** v1 runs on Cloudflare Workers on a **workers.dev** subdomain, with D1 for storage. **Rejected:** a custom domain for v1. The registered callback must match exactly, so every origin change forces a re-registration. We will pick the final origin once, later.

The canonical origin is a single constant:

```
CANONICAL_ORIGIN = "https://claim-check.PLACEHOLDER.workers.dev"   // PLACEHOLDER, not a real origin
CALLBACK_URL     = CANONICAL_ORIGIN + "/auth/agent/callback"
```

**The value above is a PLACEHOLDER.** `docs/manifest.draft.json` uses the same placeholder for `app_origin`, `base_url`, and `login_url`, and the manifest URL sits on the same origin. All four must be replaced together with the real origin before registration. Nothing in the Worker builds an origin from the `Host` header.

Secrets the Worker needs (names only; values never go in the repo, chat, or docs):
- `RAFT_CLIENT_ID`: the Raft OAuth client ID. It is not sensitive but is stored next to its secret.
- `RAFT_CLIENT_SECRET`: the Raft OAuth client secret. It is delivered once via the owner-only handoff (Raft Manual, `integration` topic).
- `SESSION_SECRET`: the HMAC key used to hash session IDs.
- `GITHUB_TOKEN`: a fine-grained personal access token on the project owner's GitHub account, read-only on public repositories.

The manifest is served by the Worker at `CANONICAL_ORIGIN + "/.well-known/raft-agent-manifest.json"`. Both live example apps serve theirs at that path (tdoc.dev and raft-artifacts.com, HTTP 200). The URL is also passed explicitly at registration.

**Distribution:** Claim Check is published to the Raft Marketplace. While the listing is in review, it is shared through a private share link.

## Open questions

**Preflight** means this sequence against the real origin: `raft integration login` → `raft integration invoke --list-actions` → one real action succeeds. This design treats the items under 2, and the exact effect of `credential_boundary`, as unproven until preflight passes.

1. What is the real workers.dev subdomain (the real `CANONICAL_ORIGIN`)? Another lane is setting it up.
2. VERIFY AT PREFLIGHT, not settled:
   - (a) Does the agent CLI call `login_url` with `GET ?code=…`?
   - (b) Does the token endpoint expect `client_secret_post` or `client_secret_basic`?
   - (c) Does the CLI cookie jar honour `Path=/api/agent` and `SameSite=Strict` when it replays the cookie on actions?
3. What are GitHub's current rate limits and secondary-limit behaviour? Re-verify against GitHub's docs before implementation.
4. Does Raft send an uninstall notification when a server uninstalls Claim Check?
