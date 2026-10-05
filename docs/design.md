# Claim Check: Phase 1 design

Claim Check is a Raft Connected App, hosted on Cloudflare Workers, that any Raft server can install. An agent sends a structured claim (for example "PR #312 in acme/widgets is merged"). Claim Check checks it **read-only** against its source of truth, which in v1 means the public GitHub REST API. It returns a receipt with one verdict per claim: **confirmed ✅**, **contradicted ❌**, or **can't check ⚠️**. Each verdict comes with the time of the read, the exact endpoint read, what the read proves and does not prove, and which facts were verified and which were inferred. Claim Check never executes anyone's code and never writes to GitHub. It turns the proof-of-work receipt recipe (`.ref/receipts.md`) into a product.

This document covers design only. The manifest draft is `docs/manifest.draft.json`. Every origin below is a placeholder (see [Hosting](#hosting)).

**Manifest schema string (provisional): `"raft-agent-manifest.v0"`.** The two example manifests disagree. `.ref/manifest-example-tdoc.json` uses `raft-agent-manifest.v0`, and `.ref/manifest-example-artifacts.json` uses `slock-agent-manifest.v0`. We pick the `raft-` string for three reasons. The product is named Raft throughout the pack. `.ref/integration.md` says the "former `slock_builtin` Connected App class is retired", which suggests `slock` is the older name. And the `slock-` example comes paired with other `slock_`-prefixed values (`slock_managed_token`). We rejected copying the `slock-` string. It belongs to the larger, more feature-rich example, but nothing in the pack says new manifests should use it. The pack also never says which strings Raft's parser accepts, so this choice is listed under [Open questions](#open-questions).

## Actions

**Decision:** v1 has three manifest actions: `check_claims`, `get_receipt`, and `get_session`. All three are `POST` under `/api/agent/actions/`, require the service session cookie, and return JSON. Claims are **structured objects** with a `kind` discriminator and typed fields. Claim Check never interprets free text. **Rejected:** a free-text claim parsed by a model. A model can misread a claim and then check the wrong thing, and a receipt for the wrong thing is the proxy-receipt failure that `.ref/receipts.md` warns about.

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
- `commit_on_branch`: Claim Check compares the branch with the SHA. A compare `status` of `identical` or `behind` (the SHA is an ancestor of the branch head) → ✅. A status of `ahead` or `diverged` → ❌. A branch that returns 404 on a readable public repo → ❌. A SHA that returns 404 or 422 → ❌ `commit_not_found`.
- `issue_closed`: `state == closed` → ✅, and `state_reason` is reported but not judged. `state == open` → ❌. If the response has a `pull_request` key → ⚠️ `wrong_kind` (use `pr_state`). A 301 (the issue was transferred) → ⚠️ `issue_moved`, recording the `Location` without following it. A 410 → ⚠️ `issue_deleted`.
- `tag_exists`: a 200 → ✅. If `sha` was given, the peeled target must equal it, otherwise ❌. A 404 → ❌.
- `release_published`: a 200 with `draft == false` → ✅, with `prerelease` reported. A 404 → ❌. Our public-only token cannot see drafts, so a draft also reads as 404, and the claim "published" is false either way.
- Any other `kind`, or a known kind missing a required field, → ⚠️ `unsupported_claim_kind` or `invalid_claim`. Claim Check never guesses.

### `check_claims`

`POST /api/agent/actions/check-claims`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `claims` | array of claim objects | yes | 1–20 structured claims as described above. Order is preserved in the results. |

Response `200`. A receipt is stored and returned even when some or all verdicts are ⚠️:

```json
{
  "receipt_id": "rcpt_EXAMPLEONLY0000000000000000",
  "created_at": "2026-10-06T09:00:03Z",
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

- `verdict` is one of `confirmed`, `contradicted`, or `cant_check`. `symbol` is ✅, ❌, or ⚠️. `reason` is a stable code, always set for ❌ and ⚠️. `retry_after_seconds` is set only when retrying could change a ⚠️.
- `verified` holds field values copied verbatim from a source response, each with the endpoint and field it came from. `inferred` holds every statement Claim Check derived by combining or interpreting fields, each with its rule. For example: "SHA is reachable from branch, inferred from compare status `behind`."
- `source.reads` lists every read that contributed to the verdict, in order. It records the endpoint path and HTTP status, never request headers or the token.

Errors return `{ "error": "<code>", "hint": "<one sentence>" }`, which is the shape the Raft CLI surfaces (`.ref/integration.md`):
- `400 invalid_request`: the body is not an object, `claims` is missing, `claims` is not an array or is empty, or it has more than 20 items. A malformed *individual* claim does not fail the request. That claim gets ⚠️ `invalid_claim` or `unsupported_claim_kind`.
- `401 not_authenticated`: the session is missing, expired, or revoked. The fix is to re-run `raft integration login`.
- `403 not_authorized`: the server is blocked, or the session has no server context.
- `429 rate_limited`: the request exceeds a Claim Check limit. The response includes `Retry-After`, and no receipt is created.
- `500 internal_error`: no receipt is created. Claim Check never returns partial results without a stored receipt.

### `get_receipt`

`POST /api/agent/actions/get-receipt`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt_id` | string | yes | The `receipt_id` returned by `check_claims`. |

Response `200`: the stored receipt, byte-for-byte the body `check_claims` returned, plus `"expires_at"`. A stored receipt is immutable and is never re-checked. To re-check, call `check_claims` again, which creates a new receipt.

Errors: `401 not_authenticated`. `404 receipt_not_found` covers every one of these cases with the identical body: an unknown ID, a malformed ID, an expired or deleted receipt, and a receipt owned by another server. `429 rate_limited`.

### `get_session`

`POST /api/agent/actions/get-session`. It takes no parameters. This is the documented read-only check an agent runs after `raft integration login` to confirm the service session really works (`.ref/integration.md` says a stored cookie is "unverified" until such a check passes).

Response `200`:
`{ "principal": { "id", "type", "display_name" }, "server": { "id", "slug", "name" }, "session_expires_at" }`.

Errors: `401 not_authenticated`, `403 not_authorized`.

## Login with Raft

**Decision:** the callback path is exactly `/auth/agent/callback`, and the full callback URL is the constant `CALLBACK_URL = CANONICAL_ORIGIN + "/auth/agent/callback"`. The Worker never builds it from the `Host` header, `X-Forwarded-*`, or the request URL. The callback mints Claim Check's own opaque service session cookie, with a path that covers every action endpoint. **Rejected:** a stateless signed cookie such as a JWT. It cannot be revoked before it expires, and revocation is a lifecycle requirement (`.ref/login-with-raft.md`).

Registration uses the agent flow from `.ref/login-with-raft.md`. It runs `raft integration app prepare register` with `--redirect-url` set to the exact `CALLBACK_URL` and the scopes `openid` and `profile`. A human commits the card.

**Callback (`GET /auth/agent/callback`).** The callback runs these steps in order:
1. Read the one-time `code`. The agent CLI handoff does not run a relying-party state/PKCE flow (`.ref/integration.md`), so v1 serves agent principals only. Human browser login, which would need `state`/PKCE, is out of scope for v1.
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

An expired or revoked session gets `401 not_authenticated`, and the fix is to re-run `raft integration login`. The fix is never a workaround. Because Claim Check keeps no Raft token, it cannot re-check membership mid-session. The 24-hour cap bounds that window.

**Request to server mapping (identity is not authorization).** Each action request resolves cookie → hashed ID → `sessions` row → `server_id`. The server comes **only** from the session, which comes from the token-bound `serverinfo`. Any server field in the body or headers is ignored. Access is allowed only if every layer passes:
- **Granted scopes:** `openid` and `profile` are present.
- **Server binding:** the token was issued for this server's installation, and the server is not in `blocked_servers`.
- **App-local policy:** in v1, any principal of an installed server may call `check_claims` and may read that server's receipts.

If any layer fails, the request fails closed with the generic `401` or `403`.

## GitHub access

**Decision:** v1 reads GitHub **with a token** (the `GITHUB_TOKEN` secret). The token is a fine-grained token restricted to **public repositories, read-only**, so Claim Check checks public repos only. **Rejected:** unauthenticated reads. The limit is per egress IP, and Workers share egress IPs with other tenants, so Claim Check could be rate-limited by traffic it does not control. **Also rejected:** a token with private-repo access. It is shared by every installing server, so any server could read the state of a private repo it has no right to see.

GitHub limits we rely on. **NEEDS RE-VERIFICATION against GitHub's current docs before implementation:**
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

**Decision:** a single **D1** database holds receipts, sessions, rate-limit windows, and the server block list. **Rejected:** KV. It is eventually consistent, so a revoked session or an exhausted rate window can stay valid on another edge for up to about a minute. It also cannot run the `id AND server_id` lookup as one indexed query. **Also rejected:** no storage at all, because `get_receipt` and revocation both need state.

```
receipts(
  id            TEXT PRIMARY KEY,      -- "rcpt_" + 26 chars base32 of 128 random bits
  server_id     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  principal_type TEXT NOT NULL,        -- "agent" in v1
  created_at    TEXT NOT NULL,         -- RFC 3339 UTC
  expires_at    TEXT NOT NULL,         -- created_at + 90 days
  confirmed     INTEGER NOT NULL,
  contradicted  INTEGER NOT NULL,
  cant_check    INTEGER NOT NULL,
  body_json     TEXT NOT NULL          -- the exact check_claims response body
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

rate_windows(
  key           TEXT PRIMARY KEY,      -- e.g. "claims:server:<id>:<hour>", "req:principal:<id>:<minute>"
  count         INTEGER NOT NULL,
  expires_at    TEXT NOT NULL
)

blocked_servers(
  server_id     TEXT PRIMARY KEY,
  blocked_at    TEXT NOT NULL,
  reason        TEXT NOT NULL
)
```

`body_json` holds only extracted fields and endpoint paths. It never holds raw GitHub response bodies, request headers, or any token. **Retention:**
- Receipts: 90 days, then hard-deleted. After that, `get_receipt` returns the same 404 as for an unknown ID.
- Sessions: rows are deleted 7 days after `expires_at` or `revoked_at`, whichever comes first.
- Rate windows: deleted once expired.

A daily scheduled purge does the deletion.

## Receipt visibility

**Decision:** a receipt is visible only to principals of the **Raft server that requested it**. Any agent on that server may read it, so a receipt can be handed off within the server, and no other server can. `get_receipt` runs exactly one query: `SELECT … WHERE id = ? AND server_id = ? AND expires_at > now`. The `server_id` comes from the session. When that query returns no row, the response is the identical `404 receipt_not_found` body, whether the ID is unknown, malformed, expired, or owned by another server. Nothing reveals that a receipt exists elsewhere. **Rejected:** public share URLs. A public link would turn a receipt into a bearer credential and leak a private server's activity, which cuts against Raft's members-only defaults.

A receipt has a **stable ID but no URL** in v1. Agents cite `receipt_id` in handoffs, and a reader on the same server fetches the receipt with `get_receipt`. A member-only HTML view that requires login is a possible later addition, not v1.

## Rate limits and abuse

**Decision:** Claim Check enforces fixed-window limits in D1 and checks them **before** any GitHub read:

| Limit | Value |
| --- | --- |
| Claims per `check_claims` request | max **20** |
| `check_claims` requests per agent | **6 / minute** |
| Claims per agent | **100 / hour** |
| Claims per server (all its principals) | **300 / hour** |
| `get_receipt` + `get_session` per agent | **120 / minute** |
| Global GitHub reserve | stop new checks while `x-ratelimit-remaining < 500` |

If any of these limits is exceeded, the response is `429 rate_limited` with `Retry-After` and **no receipt**. The global reserve keeps one server from draining the shared token budget. **Rejected:** caching GitHub responses to save budget. A cached read would give a stale verdict with a fresh `checked_at`, which is exactly the false receipt this product exists to prevent.

**When GitHub's own limit is hit mid-request**, the claims already read keep their real verdicts. Every remaining claim gets ⚠️ `github_rate_limited` with `retry_after_seconds`, taken from `Retry-After` or `x-ratelimit-reset`. The request still returns `200` with a stored receipt. Claim Check never substitutes a stale, cached, or guessed verdict.

Abuse controls:
- Requests are capped at 64 KB.
- Each GitHub read times out after 10 seconds.
- Redirects are never followed.
- Claim Check reads only `api.github.com` paths built from validated typed fields, so a claim cannot make Claim Check fetch an arbitrary URL.
- An operator can add a server to `blocked_servers`.

## What a receipt proves and does not prove

**Decision:** each result names its **acceptance surface**, which is the exact GitHub object and field the claim is about. It then states `proved` and `not_proved` and separates `verified` (values read verbatim, with endpoint and field) from `inferred` (conclusions, with the rule), following `.ref/receipts.md`. Claim Check checks **only the surface the claim names** and never a nearby proxy. **Rejected:** a single "looks good" boolean, because it is the "unscoped receipt" failure in `.ref/receipts.md`, where a reader takes the receipt to prove more than it does.

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

**Decision:** v1 runs on Cloudflare Workers on a **workers.dev** subdomain, with D1 for storage. **Rejected:** a custom domain for v1. The registered callback must match byte-for-byte, so every origin change forces a re-registration. We will pick the final origin once, later.

The canonical origin is a single constant:

```
CANONICAL_ORIGIN = "https://claim-check.PLACEHOLDER.workers.dev"   // PLACEHOLDER, not a real origin
CALLBACK_URL     = CANONICAL_ORIGIN + "/auth/agent/callback"
```

**The value above is a PLACEHOLDER.** `docs/manifest.draft.json` uses the same placeholder for `app_origin`, `base_url`, and `login_url`. All three must be replaced together with the real origin before registration. Nothing in the Worker builds an origin from the `Host` header.

Secrets the Worker needs (names only; values never go in the repo, chat, or docs):
- `RAFT_CLIENT_ID`: the Raft OAuth client ID. It is not sensitive but is stored next to its secret.
- `RAFT_CLIENT_SECRET`: the Raft OAuth client secret. It is delivered once via the owner-only handoff (`.ref/integration.md`).
- `SESSION_SECRET`: the HMAC key used to hash session IDs.
- `GITHUB_TOKEN`: the fine-grained GitHub token, public repositories read-only.

The manifest is served by the Worker at `CANONICAL_ORIGIN + "/manifest.json"`. The path is provisional; see Open questions.

## Open questions

1. Does Raft's manifest parser accept `"raft-agent-manifest.v0"`, and is `"slock-agent-manifest.v0"` deprecated? (Our choice is provisional.)
2. Does the manifest parameter `type` vocabulary accept `"array"` for `claims`, or must callers send claims via `--data-json`?
3. Should the manifest declare `credential_boundary: {"storage": "slock_managed_token"}` like the artifacts example, and what does that value change?
4. At what URL or path does Raft expect a Connected App's manifest to be served?
5. What workers.dev subdomain (the real `CANONICAL_ORIGIN`) will v1 use?
6. Does the agent CLI handoff call `login_url` with `GET ?code=…`, and does the token endpoint expect `client_secret_post` or `client_secret_basic`?
7. Does the CLI cookie jar honour `Path=/api/agent` and `SameSite=Strict` when it replays the cookie on actions?
8. Which GitHub account or org owns `GITHUB_TOKEN`: a fine-grained PAT, or a GitHub App installation token?
9. Are GitHub's current limits still 60/h unauthenticated and 5,000/h authenticated, and how do secondary limits behave? (Re-verify against GitHub's docs.)
10. Are the limits right: 20 claims per request, 6 requests/min and 100 claims/h per agent, 300 claims/h per server?
11. Is a 90-day receipt retention acceptable?
12. Is a 24-hour session lifetime acceptable for agents?
13. Does Raft notify the app when a server uninstalls it, so Claim Check can revoke that server's sessions at once?
14. Should a server admin be able to restrict Claim Check to an allowlist of agents, or is "any principal of an installed server" right for v1?
15. Should human browser login (with state/PKCE) and a member-only receipt page be in v1.1?
16. Should Claim Check be published to the Marketplace or stay server-local first?
