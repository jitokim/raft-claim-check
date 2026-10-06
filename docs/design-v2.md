# Claim Check: v2 design

Claim Check v2 checks work **where the work happens**, and the app keeps the ledger. An open-source Go CLI, `claim-check`, runs a command on the agent's own machine, records what happened, and signs the record with a per-machine ed25519 key. It submits the signed receipt through `raft integration invoke`, so it reuses the agent's existing Raft Agent Login session. The Claim Check app is a Cloudflare Worker. It checks the signature and the key binding, stores the receipt, and serves it back to principals of the same Raft server. The app never runs code and never reads an external repository.

This document covers design only. It replaces [docs/design.md](design.md) (v1) wherever the two differ. The manifest draft is `docs/manifest.draft.json`. Every origin below is the canonical origin `https://claim-check.ohmygraph.workers.dev`, as in v1.

## What changed from v1

**Decision:** v2 is "verify where the work happens, the app keeps the ledger". v1 had the Worker query GitHub on the agent's behalf with one central token. That did nothing for local work or non-GitHub repos, and a single shared token stops scaling as usage grows. In v2 the CLI records a command run (`claim-check run`) or a file hash (`claim-check attest`) on the agent's machine and signs it. The Worker checks the signature against a key registered to (Raft server, agent principal) and keeps the ledger. **Rejected:** keeping the central-token GitHub checker and adding local receipts beside it, because the shared token's read budget and blast radius remain the bottleneck either way.

**Carried over unchanged** from `docs/design.md`. These sections are not rewritten here, and v2 relies on them as written:
- `## Login with Raft`: the callback, the opaque `cc_session` cookie (`Path=/api/agent`), the 24-hour lifecycle, revocation, and the request-to-server mapping. Where it says "the v1 actions" or names `check_claims`, read the v2 action set in [Actions](#actions). The app-local policy is now: any principal of an installed server may call every v2 action, and key actions apply only to that principal's own keys.
- `## Hosting`: the workers.dev origin, `CANONICAL_ORIGIN`, `CALLBACK_URL`, the manifest path, and distribution. The secret `GITHUB_TOKEN` is removed. `RAFT_CLIENT_ID`, `RAFT_CLIENT_SECRET` and `SESSION_SECRET` stay.
- `## Receipt visibility`: the server-scoped read rule and the identical `404` (see [Receipt visibility](#receipt-visibility) for the one addition).
- From `## Actions`: `get_session` as specified, and the `{ "error": "<code>", "hint": "<one sentence>" }` error shape.
- From `## Storage`: the D1 choice and the `sessions` and `blocked_servers` tables.
- From `## Rate limits and abuse`: the atomic single-statement reservation in `rate_reservations`, the 64 KB request cap, and "a failed request is not refunded".
- From `## Open questions`: items 1 (preflight) and 3 (uninstall notification).

**Dropped:** the `check_claims` action and all its claim kinds and verdict rules, the whole `## GitHub access` section, the `GITHUB_TOKEN` secret, the shared GitHub read budget (`github_budget` table and its reservation statements), and open question 2 (GitHub rate limits). The v1 implementation stays on its own branch and is not merged into `main`.

**Reversed on purpose:** v1's `## oh-my-graph runs as evidence` rejected evidence the claimant supplies as self-attestation. v2 accepts exactly that kind of evidence, but labels it honestly: everything the CLI records is **asserted** by the key holder, and only the signature, key binding, submitter and receipt time are **verified** by the app (see [Verification](#verification)). An oh-my-graph run can be wrapped with `claim-check run` like any other command.

**Later and optional:** a GitHub adapter that plugs into this ledger without a central token (see [GitHub adapter (later)](#github-adapter-later)).

## Threat model

**Decision:** Claim Check defends the **integrity and attribution** of receipts: who signed, with which registered key, on which server, and that nothing changed after signing. It does **not** defend the **truth** of what the signer recorded. **Rejected:** claiming tamper-proof execution evidence, which would need remote attestation of the agent's machine (a TPM or TEE quote) that Raft agents do not have.

**Assets:**
- The per-machine private keys.
- The ledger: stored receipts and the key-to-principal bindings.
- Receipt contents, which can contain redacted output tails, argv, and git remotes.
- Service sessions, as in v1.

| Actor / attack | Defence |
| --- | --- |
| **Honest agent** runs `claim-check run -- go test ./...` | The receipt records argv, exit code, output hashes and git state faithfully. Every run is submitted by default, failures included, so the ledger holds the red runs too. |
| **Owner who deliberately lies: runs a different command** than the one claimed | **Not defended.** The receipt shows the argv that actually ran. A reader must compare it with the claim (see the proxy trap in [What a receipt proves and does not prove](#what-a-receipt-proves-and-does-not-prove)). |
| **Lying owner: edits the output** | **Not defended** against the key holder. Output hashes cover the bytes the CLI saw. Anyone holding the full output can recompute the hash, so a published log that does not match is caught. |
| **Lying owner: fakes git state** (sets a remote URL, checks out a different HEAD, hides a dirty tree) | **Not defended.** `git.remote_url`, `git.head` and `git.dirty` are asserted. The app never reads the repo. |
| **Lying owner: uses a patched CLI**, or signs a hand-made payload with the key | **Not defended.** `cli.version` is asserted. Anyone holding the key can sign any payload. This is the limit that every receipt states. |
| **Stolen or leaked private key** | Revoke with `revoke_key`, optionally with `compromised_since`. New submissions with that key get `403 key_revoked`. Receipts received at or after `compromised_since` are flagged. The window between the theft and the revocation, or before `compromised_since` if it is set too late, is **not defended**. |
| **Stolen Raft session, no key.** An attacker holding a victim's valid Claim Check session (or Raft agent login) calls `register_key` with a key the attacker generated | **Not defended** beyond the session itself. Proof of possession only proves possession of that new key, so the attacker can register up to the 5-active-key cap and sign receipts attributed to the victim. Key binding is only as strong as the Raft session, and v1's 24-hour session cap bounds the window. Mitigation: the owner runs `list_keys`, sees a key they do not recognise (`label`, `registered_at`, `key_id`), and revokes it with `revoke_key` (reason `compromised`, with `compromised_since`), which flags receipts received at or after that time. |
| **Another process on the same OS user reads the key file** (including another agent profile run by the same OS user) | **Not defended** beyond file mode `0600` and the per-agent profile path. Same-user isolation is the host's job. |
| **Replay of an old receipt** | The receipt ID is derived from the signed payload, which includes a random `nonce`. Resubmitting the same envelope returns the existing record (`200`, `duplicate: true`) and creates nothing. Payloads signed more than 7 days before submission are refused. A replay under another principal fails the key binding. |
| **Agent of another server submits a receipt** signed by a key it does not own | The key must be bound to the submitting session's (server, principal), and `payload.bound_to` must match the session. Otherwise `403 key_not_registered` or `400 binding_mismatch`. |
| **Agent of another server reads receipts** | Reads are scoped to the session's server, with the identical `404 receipt_not_found` (v1 `## Receipt visibility`). |
| **Registering someone else's public key as your own** | `register_key` requires proof of possession: a statement naming the session's server and principal, signed by the private key itself. A public key can be bound to only one (server, principal), and a revoked key can never be registered again. |
| **Compromised Worker or D1** | Partly defended. The stored envelope keeps the original payload and signature, so anyone with the signer's public key (from `claim-check key show` on the signer's machine) can re-verify a receipt offline with `claim-check verify`. An attacker cannot forge a signature. **Not defended:** deleting receipts, binding an attacker's key to a principal, or lying in the `ledger` section (`received_at`, key status). |
| **Secrets leak through a receipt** | The [Redaction policy](#redaction-policy) masks known secret formats before signing, and receipts are server-private. **Not defended:** secrets in unknown formats. A hash of a very short output (for example a command that prints only a token) is a guessing oracle for that output. |
| **Session theft, oversize payloads, flooding** | v1's session design, the 64 KB cap, field caps and [Rate limits and abuse](#rate-limits-and-abuse). |

**What a receipt cannot protect against, plainly:** a receipt proves "this registered key, on this machine, ran this command and got this result", and only as far as the key holder is honest. An owner who deliberately lies can produce a validly signed receipt for a run that never happened. Claim Check makes such a lie **attributable**, because it is signed by a key bound to that principal and recorded in the ledger. It does not make the lie **impossible**.

## CLI

**Decision:** the CLI lives in **this repository** under `cli/` as its own Go module, released as a static binary for Linux and macOS. **Rejected:** a separate repository, because the receipt schema, the canonicalization test vectors and the Worker's verifier must change together in one reviewed commit.

The CLI has **no authentication of its own**. It never reads Raft's cookie store, never calls the Worker over HTTP, and never handles a token. Every call to the app goes through `raft integration invoke`.

### Commands

| Command | What it does |
| --- | --- |
| `claim-check run [--require-receipt] [--quiet] [--redact-arg N]... -- <cmd> [args...]` | Runs `<cmd>`, records it, signs, submits. |
| `claim-check attest --file <path>` | Records the SHA-256 and size of one regular file, signs, submits. |
| `claim-check key init` | Generates this profile's key on this machine. Refuses if a key already exists. |
| `claim-check key register [--label <text>]` | Proves possession and binds the key to (server, principal) through `register_key`. |
| `claim-check key show` | Prints `key_id`, the public key and the binding. Never prints the private key. |
| `claim-check key list` | Calls `list_keys`. |
| `claim-check key revoke [--key-id <id>] --reason rotated\|lost\|compromised [--compromised-since <time>]` | Calls `revoke_key`. Works without the private key. |
| `claim-check key rotate [--force]` | `flush` first, and refuses without changing anything if receipts signed by the old key are still pending. Then `key init` for a new key, `key register`, then `key revoke --reason rotated` for the old key. `--force` rotates anyway, and those pending receipts are lost (moved to `rejected/` on the next `flush`). |
| `claim-check flush` | Resubmits spooled receipts. |
| `claim-check verify <receipt.json> [--public-key <ed25519:...>]` | Offline check: canonicalizes the payload, checks the signature and the receipt ID. Makes no network call. |

### What `run` records

`run` records exactly the fields in [Receipt schema](#receipt-schema): argv (redacted), exit code or terminating signal, wall-clock start and finish times, monotonic duration in milliseconds, SHA-256 and byte count of the full stdout and of the full stderr, a redacted tail of each, the git remote URL, HEAD and dirty flag of the working directory's repository, the signing time, and the CLI name, version, OS and architecture. It records nothing else: no environment variables, no stdin, no full output, no absolute working directory, no hostname and no user name.

`attest` records the file's path relative to the repository root (or its base name outside a repository), its SHA-256 over the full contents, its size, and the same git, time and CLI fields. It refuses directories, devices and symlinks that point outside the repository.

### Pass-through

The child must behave as if `claim-check` were not there:
- **stdin** is inherited directly by the child. The CLI never reads it.
- **Environment** is passed to the child unchanged.
- **stdout and stderr** are read from two pipes and copied byte-for-byte, unbuffered, to the CLI's own stdout and stderr, while being hashed. The CLI never reorders, re-encodes or strips them. One visible difference is that the child sees pipes, not a TTY, so some tools turn off colour (see [Open questions](#open-questions)).
- **Signals:** `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` are forwarded to the child. The CLI waits for the child to exit.
- **The CLI's own messages** are written to stderr only after the child has exited and both pipes are drained, as one line prefixed `claim-check:` with the receipt ID and the submit outcome. These bytes are not part of the hashed child stderr. `--quiet` suppresses the line.

**Exit-code policy.** **Decision:** once the child has started, `claim-check run` exits with the child's exit code, or `128 + N` if signal N killed it, exactly as a shell would report it. A receipt problem never changes a failing exit code. **Rejected:** always failing when the receipt could not be submitted, because that would break scripts that wrap commands and would hide the child's real result.
- Before the child starts, the CLI uses its own codes: `64` for usage errors, and `78` when there is no usable key, the key is not registered locally, or the key file permissions are wrong. Without a usable key, `run` refuses to start the child, because a run that silently produces no receipt is the failure this tool exists to prevent. To run without a receipt, run the command without `claim-check`.
- If the command cannot be executed, the exit code is `127` (not found) or `126` (not executable), and no receipt is made because nothing ran.
- `--require-receipt`: if the child exited `0` but the receipt was not stored by the app, exit `75`. A non-zero child exit code is still passed through unchanged. The `claim-check:` stderr line says which case applied.

### Where the key lives

The key file **must** live under the per-agent profile HOME/XDG tree that `raft integration env --service claim-check` prints, never under the host user's global HOME. This is the credential red line in the Raft Manual, `integration` topic: a manifest-backed service's local credentials live under the per-agent profile tree.

The CLI resolves the tree by running `raft integration env --service claim-check` and reading `XDG_CONFIG_HOME` and `XDG_STATE_HOME` from its output, falling back to `<profile HOME>/.config` and `<profile HOME>/.local/state`. It never falls back to its own process's `HOME`. If the command fails or prints no profile HOME, every key command and `run` fail with exit `78` and a hint to run `raft integration login --service claim-check`.

| File | Path | Mode |
| --- | --- | --- |
| Private key (32-byte seed, raw) | `$XDG_CONFIG_HOME/claim-check/key/ed25519` | `0600`, directory `0700` |
| Key metadata: `key_id`, public key, bound server and principal | `$XDG_CONFIG_HOME/claim-check/key/key.json` | `0600` |
| Pending spool | `$XDG_STATE_HOME/claim-check/spool/<receipt_id>.json` | `0600`, directory `0700` |
| Rejected spool | `$XDG_STATE_HOME/claim-check/spool/rejected/` | `0600` |

On every load, the CLI refuses a key file whose mode grants any group or other permission, as OpenSSH does.

### Submitting

The CLI builds the request body `{"receipt": <envelope>}` and pipes it on stdin. The shell equivalent is:

```bash
# spool/<receipt_id>.json holds {"receipt": {"payload": {...}, "signature": {...}}}
raft integration invoke claim-check submit_receipt --data-file - --json < spool/<receipt_id>.json
```

In Go this is `exec.Command("raft", "integration", "invoke", "claim-check", "submit_receipt", "--data-file", "-", "--json")` with the JSON written to the child's stdin and a 30-second timeout. The JSON is never passed as a command-line argument, so it never shows up in process listings. The receipt is written to the pending spool **before** the submit call, and removed only after a `200` or `201` whose `receipt_id` equals the locally computed ID.

When the submit fails:

| Failure | CLI behaviour |
| --- | --- |
| `raft` not on `PATH`, or `raft integration` is an unknown command | Keep in spool. Hint: the machine needs a Raft CLI with Agent Login. |
| Not logged in, or `401 not_authenticated` | Keep in spool. Hint: run `raft integration login --service claim-check`, then `claim-check flush`. |
| Offline, timeout, `429`, `5xx` | Keep in spool. `flush` retries, respecting `Retry-After`. |
| `400`, `403`, `409`, `413` (the app refused this receipt for good) | Move to `spool/rejected/` with the `{error, hint}`. Never retried automatically. |

`flush` sends pending receipts oldest first and stops at the first `401` or `429`. A spooled receipt older than 7 days cannot be accepted (see [Verification](#verification)), so `flush` moves it to `rejected/`. Rejected files are deleted after 30 days.

## Receipt schema

**Decision:** a receipt is an **envelope** holding a signed `payload` and a detached `signature`. The signature covers the **RFC 8785 JSON Canonicalization Scheme (JCS)** serialization of `payload`, encoded as UTF-8. **Rejected:** signing the bytes exactly as transmitted. The body passes through `raft integration invoke`, which parses and may re-serialize the JSON, so raw bytes are not guaranteed to survive. JCS gives Go and the Worker's JavaScript the same bytes from the same value. **Also rejected:** JWS or COSE, which add header and encoding layers that a reader cannot audit by eye.

To keep JCS unambiguous, the payload contains **no floating-point numbers**. Every number is an integer within ±2^53. Payloads with duplicate object keys are rejected before canonicalization.

**Schema version strings:** `claim-check.receipt.v2` for receipts and `claim-check.key-registration.v2` for registration statements. The `schema` field is inside the signed payload, so a signature over one kind can never pass as the other.

**Receipt ID:** `"rcpt_"` + lowercase RFC 4648 base32, without padding, of the first 16 bytes of `SHA-256(JCS(payload))`, which gives 26 characters. The ID has the same shape as v1's. The CLI and the Worker compute it independently and must agree. Because it is content-derived, a resubmitted envelope maps to the same ID.

**Key ID:** `"ck_"` + the same base32 encoding of the first 16 bytes of `SHA-256(raw 32-byte public key)`.

**Encodings:** a public key is `"ed25519:" + base64url(raw 32 bytes)`, without padding. A signature is `"ed25519:" + base64url(64 bytes)`. A hash is `"sha256:" + 64 lowercase hex characters`. Times are RFC 3339 UTC with milliseconds, for example `2026-10-06T09:00:03.120Z`.

### Signed payload (`payload`)

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `claim-check.receipt.v2`. |
| `kind` | string | `run` or `attest`. |
| `nonce` | string | 16 random bytes, base64url. It makes two identical runs in the same millisecond distinct. |
| `key_id` | string | The signing key's ID. |
| `bound_to` | object | `{ "server_id": string, "principal_id": string }`, copied from the binding stored at `key register`. Must match the submitting session. |
| `cli` | object | `{ "name": "claim-check", "version": string, "os": string, "arch": string }`. Asserted. |
| `signed_at` | string | Signing time from the machine's clock. Asserted. |
| `git` | object or null | `null` outside a git repository. Otherwise `{ "remote_url": string or null, "head": string or null, "branch": string or null, "dirty": boolean }`. `remote_url` is `origin`'s fetch URL with any userinfo removed. `head` is the full 40-hex SHA, `null` before the first commit. `dirty` is true if `git status --porcelain` reports any tracked change or any untracked, non-ignored file. |
| `run` | object | Present only when `kind` is `run`. See below. |
| `attest` | object | Present only when `kind` is `attest`. See below. |

`run`:

| Field | Type | Meaning |
| --- | --- | --- |
| `argv` | array of string | The command and its arguments after argv redaction. 1 to 128 elements, at most 8 KB total. |
| `argv_redactions` | integer | The number of argv elements that were masked. |
| `cwd_rel` | string or null | The working directory relative to the repository root (`"."` at the root). `null` outside a repository. |
| `started_at`, `finished_at` | string | Wall-clock times around the child. |
| `duration_ms` | integer | Monotonic duration of the child. |
| `exit` | object | `{ "code": integer or null, "signal": string or null }`. Exactly one is non-null. |
| `stdout`, `stderr` | object | `{ "sha256": string, "bytes": integer, "tail": string, "tail_truncated": boolean, "tail_redactions": integer }`. `sha256` and `bytes` cover the **full, unredacted** stream. `tail` is at most 2,048 bytes of UTF-8 after redaction. |

`attest`:

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | The path relative to the repository root, or the base name outside a repository. |
| `sha256` | string | The hash of the full file contents. |
| `bytes` | integer | The file size. |
| `observed_at` | string | When the file was read. |

### Envelope

The CLI submits `{ "payload": {...}, "signature": { "alg": "ed25519", "key_id": string, "value": string } }`. `signature.key_id` must equal `payload.key_id`. The app stores the envelope verbatim and adds a `ledger` object that is **not signed by the CLI**. The ledger holds the app's own statements (see [Verification](#verification)).

### Example stored receipt

Every value below is a fake placeholder.

```json
{
  "receipt_id": "rcpt_exampleonly000000000000",
  "envelope": {
    "payload": {
      "schema": "claim-check.receipt.v2",
      "kind": "run",
      "nonce": "EXAMPLE-NONCE",
      "key_id": "ck_exampleonly000000000000",
      "bound_to": { "server_id": "srv_example", "principal_id": "agent_example" },
      "cli": { "name": "claim-check", "version": "2.0.0-example", "os": "darwin", "arch": "arm64" },
      "signed_at": "2026-10-06T09:00:03.120Z",
      "git": {
        "remote_url": "https://github.com/example/widgets.git",
        "head": "EXAMPLE-40-HEX-COMMIT-SHA",
        "branch": "main",
        "dirty": false
      },
      "run": {
        "argv": ["go", "test", "./...", "-token=[REDACTED:sensitive_flag]"],
        "argv_redactions": 1,
        "cwd_rel": ".",
        "started_at": "2026-10-06T09:00:00.020Z",
        "finished_at": "2026-10-06T09:00:03.050Z",
        "duration_ms": 3030,
        "exit": { "code": 0, "signal": null },
        "stdout": {
          "sha256": "sha256:EXAMPLE-STDOUT-DIGEST",
          "bytes": 18234,
          "tail": "ok  \texample.com/widgets/api\t1.204s\nok  \texample.com/widgets/store\t0.811s\n",
          "tail_truncated": true,
          "tail_redactions": 0
        },
        "stderr": {
          "sha256": "sha256:EXAMPLE-STDERR-DIGEST",
          "bytes": 0,
          "tail": "",
          "tail_truncated": false,
          "tail_redactions": 0
        }
      }
    },
    "signature": {
      "alg": "ed25519",
      "key_id": "ck_exampleonly000000000000",
      "value": "ed25519:EXAMPLE-SIGNATURE-NOT-REAL"
    }
  },
  "ledger": {
    "received_at": "2026-10-06T09:00:04.002Z",
    "expires_at": "2027-01-04T09:00:04.002Z",
    "server": { "id": "srv_example", "slug": "example" },
    "submitted_by": { "principal_id": "agent_example", "principal_type": "agent" },
    "key": {
      "key_id": "ck_exampleonly000000000000",
      "public_key": "ed25519:EXAMPLE-PUBLIC-KEY-NOT-REAL",
      "status": "active",
      "revoked_at": null,
      "compromised_window": false
    },
    "submitted_late": false,
    "acceptance_surface": "Exit status and output of argv [go test ./... -token=…] on the machine holding key ck_exampleonly000000000000",
    "verified": [
      "signature valid over JCS(payload) for key ck_exampleonly000000000000",
      "key bound to server srv_example and principal agent_example, active at received_at",
      "submitted by principal agent_example through its Claim Check session",
      "received_at from the app's clock"
    ],
    "asserted": ["run.*", "git.*", "cli.*", "signed_at"],
    "proved": ["The holder of key ck_exampleonly000000000000 signed this record of a run that exited 0"],
    "not_proved": [
      "That the command ran unmodified or at all; everything in payload is asserted by the key holder",
      "That this command tests what any claim is about",
      "That git.head is pushed, reviewed or deployed",
      "That the environment, inputs or network matched any other run"
    ]
  }
}
```

## Redaction policy

**Decision:** redaction happens in the CLI **before signing**, so the app never receives the masked values. Hashes are computed over the **full, unredacted** stdout and stderr, so anyone holding the real output can still prove it matches the receipt. **Rejected:** redacting in the Worker, because the secret would already have left the machine.

**Never recorded:** environment variables (names or values), stdin, full stdout or stderr, the absolute working directory, the hostname and the OS user name.

**Tails.** For each stream the CLI keeps the last 8 KiB of raw bytes as a scan window. It decodes the window as UTF-8, replacing invalid sequences with U+FFFD, strips ANSI escape sequences and control characters other than `\n` and `\t`, and applies the masks below. It then keeps the last **2,048 bytes**, cut at a UTF-8 character boundary. Scanning a wider window than the tail means a secret that straddles the tail's start is still masked. `tail_truncated` is true when output was dropped from the front.

**Masks.** Each match is replaced with `[REDACTED:<rule>]`, and the count goes into `tail_redactions` or `argv_redactions`. The rules:

| Rule | Matches |
| --- | --- |
| `private_key` | A whole PEM-armoured private-key block, from its header line through its footer line, including a block whose footer is not inside the window. |
| `bearer` | `Authorization:` header values and `Bearer <token>`. |
| `known_token` | Well-known vendor token formats, matched by their documented fixed prefixes: GitHub personal, OAuth, user-to-server, server-to-server and refresh tokens and fine-grained PATs; Slack bot, app, user and refresh tokens; AWS access key IDs; OpenAI-style and Anthropic-style API keys; npm access tokens. The exact regex list is versioned in the CLI source, so the CLI version recorded in the receipt identifies it. |
| `jwt` | Three base64url segments where the first starts with `eyJ`. |
| `url_userinfo` | The `user:password@` part of any `scheme://` URL. |
| `sensitive_assignment` | The value in `NAME=value`, `NAME: value` or `"NAME": "value"` when NAME matches `(?i)(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)`. |
| `env_value` | An exact occurrence of the value of any environment variable whose **name** matches the same pattern and whose value is 8 or more characters. The value is used only for matching in memory and is never recorded. |

**argv redaction.** The CLI applies the same rules to each argv element. It also masks the value of a flag whose name matches the sensitive-name pattern, both in `--name=value` form (`sensitive_flag`) and in `--name value` form (masking the next element). `--redact-arg N` (repeatable) masks the Nth argument of the child, counting from 0, in full. Unlike the output, argv has **no hash of its unredacted form**, because argv is short and a hash would be a guessing oracle for a short secret.

Redaction is best-effort. A secret in an unknown format can still reach a tail. Receipts are server-private for that reason, and the [Threat model](#threat-model) lists this risk as not defended.

## Key lifecycle

**Decision:** there is **one key per (agent profile, machine)**. The key lives in the per-agent profile tree on one machine, so it names both. **Rejected:** one key per machine, shared by every agent on it, which would let one agent sign as another and break the binding to a single principal. **Also rejected:** one key per agent profile, copied across machines, which would make "on this machine" meaningless and widen the impact of a leak. An agent working on three machines has three keys, each registered separately. Each principal on a server may have at most **5 active keys**.

**Generation.** `claim-check key init` reads 32 bytes from the OS CSPRNG (Go `crypto/rand`) as the ed25519 seed, writes it with `O_CREAT|O_EXCL` and mode `0600` under the profile path from [CLI](#cli), and writes `key.json` with the public key and `key_id`. It never prints the private key or the seed.

**Registration with proof of possession.** `claim-check key register` does the following:
1. Calls `raft integration invoke claim-check get_session --json` to learn the session's `server.id` and `principal.id`.
2. Builds a registration statement:
   ```json
   {
     "schema": "claim-check.key-registration.v2",
     "public_key": "ed25519:EXAMPLE-PUBLIC-KEY-NOT-REAL",
     "key_id": "ck_exampleonly000000000000",
     "server_id": "srv_example",
     "principal_id": "agent_example",
     "issued_at": "2026-10-06T08:59:00.000Z",
     "nonce": "EXAMPLE-NONCE",
     "label": "laptop-example",
     "cli_version": "2.0.0-example"
   }
   ```
3. Signs `JCS(statement)` with the private key, and submits `{"registration": {"payload": statement, "signature": {...}}}` to `register_key` through `--data-file -`.
4. On success, stores the binding (`server_id`, `principal_id`) in `key.json`.

The Worker accepts the statement only if all of these hold: the signature verifies under the statement's own `public_key`; `key_id` matches that key; `server_id` and `principal_id` equal the session's; and `issued_at` is within 10 minutes of the app's clock. Only the holder of the private key can produce this statement, and it names exactly one server and principal, so nobody can register another party's public key, and a captured statement is useless anywhere else. **Rejected:** a server-issued challenge round trip. It would add a second action and app-side nonce state, but no protection, because replaying the statement can only re-bind the same key to the same principal on the same server, which is idempotent. A revoked key can never be re-registered.

**Binding rules.** A public key is bound to exactly one (server, principal) pair for its whole life. Registering an already-active key for the same pair returns `200` with the existing record. Registering it for any other pair returns `409 key_bound_elsewhere`. That response reveals nothing that the key holder, the only party able to sign the statement, does not already know. Key binding is only as strong as the Raft session: anyone holding a principal's valid session can register a key they generated and sign receipts attributed to that principal (see [Threat model](#threat-model)).

**Rotation.** `claim-check key rotate` first runs `flush`. If the pending spool still holds any receipt signed by the old key after that flush (for example because the agent is offline), `rotate` refuses with a clear error and changes nothing: no new key, no revocation, no deletion. Otherwise it generates a new key, registers it, and only then revokes the old key with reason `rotated`. The old private key file is then deleted. Receipts signed by the old key stay valid. `--force` rotates anyway, and the receipts signed by the old key that are still pending are then lost: the next `flush` gets `403 key_revoked` and moves them to `rejected/`.

**Revocation.** `revoke_key` is called by the bound principal through its session and does not need the private key. Reasons are `rotated`, `lost` or `compromised`. An operator can also revoke keys directly in D1, with reason `operator`. Revocation is permanent.

**Lost key** (the machine or profile is gone): from any machine where the agent is logged in, run `claim-check key list`, then `claim-check key revoke --key-id <id> --reason lost`, then `key init` and `key register` on the new machine.

**Receipts signed by a key that is later revoked.** They are **not deleted and not re-judged**. The app cannot know when signing really happened (`signed_at` is asserted), so the only trustworthy ordering is the app's own `received_at`. A revoked key can submit nothing new, so every stored receipt was received while the key was active. `get_receipt` shows the key's **current** status (`ledger.key.status`, `revoked_at`). If the revocation set `compromised_since`, receipts with `received_at >= compromised_since` get `ledger.key.compromised_window: true`. Readers should treat those receipts as possibly forged. Receipts before that time keep their standing, and no claim is made about them beyond what it was before.

## Actions

**Decision:** v2 has six manifest actions: `register_key`, `submit_receipt`, `get_receipt`, `get_session`, `list_keys` and `revoke_key`. All are `POST` under `/api/agent/actions/`, require the `cc_session` cookie, and return JSON. Errors use v1's `{ "error": "<code>", "hint": "<one sentence>" }` body. Every action can also return v1's `401 not_authenticated`, `403 not_authorized` and `500 internal_error`, which are not repeated below. **Rejected:** a separate key-management API outside the manifest, because the CLI has no auth of its own and can only reach the app through manifest actions.

A body-carrying action declares one parameter of type `"object"`, as v1's `check_claims` did, and the CLI passes the body with `--data-file -`.

### `register_key`

`POST /api/agent/actions/register-key`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `registration` | object | yes | `{ "payload": <registration statement>, "signature": { "alg": "ed25519", "key_id", "value" } }`, as in [Key lifecycle](#key-lifecycle). |

Response `201` (new) or `200` (already active for this principal):
`{ "key_id", "public_key", "label", "status": "active", "registered_at", "server": { "id", "slug" }, "principal": { "id", "type" } }`.

Errors:
- `400 invalid_request`: the body or the statement is malformed, or the schema is unsupported.
- `400 bad_signature`: the signature does not verify, or `key_id` does not match `public_key`.
- `400 registration_mismatch`: `server_id` or `principal_id` is not the session's.
- `400 registration_expired`: `issued_at` is more than 10 minutes from the app's clock.
- `409 key_bound_elsewhere`.
- `409 key_revoked`.
- `409 too_many_keys`: 5 active keys already.
- `429 rate_limited`.

### `submit_receipt`

`POST /api/agent/actions/submit-receipt`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt` | object | yes | The envelope `{ "payload", "signature" }` from [Receipt schema](#receipt-schema). |

Response `201`: the stored receipt (`receipt_id`, `envelope`, `ledger`) with `"duplicate": false`. Response `200`: the already-stored receipt with `"duplicate": true` when the same payload was stored before. `duplicate` is a response flag, not part of the stored body.

Errors:
- `413 receipt_too_large`: the body is over 64 KB.
- `400 invalid_request`: not an object, `receipt`, `payload` or `signature` missing, or duplicate keys.
- `400 schema_unsupported`: unknown `schema` or `kind`.
- `400 binding_mismatch`: `payload.bound_to` is not the session's server and principal, or `signature.key_id` is not `payload.key_id`.
- `403 key_not_registered`: unknown key, or key bound to another principal or server. Both cases get the same body.
- `403 key_revoked`.
- `400 bad_signature`.
- `400 schema_invalid`: a field has the wrong type or length, or the fields are inconsistent. The `hint` names the field.
- `400 clock_skew`: `signed_at` is more than 5 minutes in the future.
- `400 receipt_too_old`: `signed_at` is more than 7 days ago.
- `429 rate_limited`, with `Retry-After`.

### `get_receipt`

`POST /api/agent/actions/get-receipt`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt_id` | string | yes | The `receipt_id` returned by `submit_receipt` or printed by the CLI. |

Response `200`: the stored receipt as `submit_receipt` returned it, without `duplicate`, with `ledger.key` updated to the key's **current** status. The stored envelope and every other ledger field never change.

Errors: `404 receipt_not_found` (unknown, malformed, expired, or other-server, all with the identical body, as in v1), and `429 rate_limited`.

### `get_session`

Carried over unchanged from v1 (`docs/design.md`, `## Actions`): `POST /api/agent/actions/get-session`, no parameters, response `{ "principal": { "id", "type", "display_name" }, "server": { "id", "slug", "name" }, "session_expires_at" }`. The CLI also uses it in `key register` to learn the server and principal IDs it must sign.

### `list_keys`

`POST /api/agent/actions/list-keys`. It takes no parameters.

Response `200`: `{ "keys": [ { "key_id", "public_key", "label", "status": "active" | "revoked", "registered_at", "revoked_at", "revoked_reason", "compromised_since" } ] }`. It lists only the calling principal's keys on the session's server, newest first, revoked ones included.

Errors: `429 rate_limited`.

### `revoke_key`

`POST /api/agent/actions/revoke-key`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `key_id` | string | yes | A key bound to the calling principal on this server. |
| `reason` | string | yes | `rotated`, `lost` or `compromised`. |
| `compromised_since` | string | no | RFC 3339 time. Allowed only with `compromised`. Must not be in the future or earlier than the key's `registered_at`. Defaults to the key's `registered_at` when the reason is `compromised`, which flags every receipt from that key. |

Response `200`: the key record as in `list_keys`, with `status: "revoked"`. Revoking an already-revoked key returns `200` with the existing record and does not change `compromised_since`.

Errors: `400 invalid_request`, `404 key_not_found` (unknown key or another principal's key, with the identical body), and `429 rate_limited`.

## Verification

**Decision:** on `submit_receipt` the Worker runs these steps **in order** and stops at the first failure. Cheap, unauthenticated checks come first, and every step that costs CPU comes after the rate-limit reservation. **Rejected:** verifying the signature before the reservation, which would let a flood of bad signatures burn CPU for free.

1. **Size.** Reject a body over 64 KB with `413`, counted while streaming. A `Content-Length` header alone is not trusted.
2. **Session.** Cookie → hashed ID → `sessions` row that is not expired or revoked. Otherwise `401`.
3. **Principal and server.** Scopes present and server not in `blocked_servers`, as in v1. The server and principal come only from the session. Otherwise `403`.
4. **Shape.** Parse JSON with duplicate-key detection. `receipt` must be an object with `payload` and `signature` objects. Otherwise `400 invalid_request`.
5. **Rate-limit reservation.** One atomic statement (see [Rate limits and abuse](#rate-limits-and-abuse)). Otherwise `429`.
6. **Schema version.** `payload.schema` is `claim-check.receipt.v2`, and `kind` is `run` or `attest`. Otherwise `400 schema_unsupported`.
7. **Binding fields.** `payload.bound_to` equals the session's (server_id, principal_id), and `signature.key_id` equals `payload.key_id`. Otherwise `400 binding_mismatch`.
8. **Key lookup and binding.** `SELECT … FROM keys WHERE key_id = ? AND server_id = ? AND principal_id = ?`. No row gives `403 key_not_registered`. A row with `revoked_at` set gives `403 key_revoked`.
9. **Signature.** Compute `JCS(payload)` from the parsed value, then verify the ed25519 signature with WebCrypto against the stored public key, rejecting non-canonical signature encodings. Otherwise `400 bad_signature`.
10. **Schema checks.** Every field's type, format, length and cap from [Receipt schema](#receipt-schema) and [Redaction policy](#redaction-policy), plus consistency: exactly one of `run` or `attest` matching `kind`; `exit.code` xor `exit.signal`; `started_at <= finished_at <= signed_at`; no floats. Otherwise `400 schema_invalid`.
11. **Timestamp skew window.** `signed_at <= received_at + 5 min`, otherwise `400 clock_skew`. `signed_at >= received_at − 7 days`, otherwise `400 receipt_too_old`. A receipt signed more than 10 minutes before it was received is stored with `ledger.submitted_late: true`, which is normal for receipts sent from the spool.
12. **Replay and duplicates.** Derive `receipt_id` from `JCS(payload)`. `INSERT … ON CONFLICT(id) DO NOTHING`. If nothing was inserted, return the stored row with `200` and `duplicate: true`. Because a key belongs to exactly one (server, principal), a stored row with the same ID always belongs to the same server.
13. **Store** the envelope verbatim, plus the `ledger`, and return `201`.

### Verified by the app vs asserted by the CLI

| Verified by the app (in `ledger.verified`) | Asserted by the key holder (in `ledger.asserted`) |
| --- | --- |
| The signature is valid over `JCS(payload)` for `key_id`, so the payload is unchanged since signing. | Everything inside `payload.run` and `payload.attest`: argv, exit code, signal, durations, hashes, byte counts, tails. |
| The key was registered with proof of possession, is bound to this server and principal, and was active at `received_at`. | `payload.git`: remote, HEAD, branch, dirty. |
| The submitting session's principal and server. | `payload.cli` (name, version, OS, architecture). Nothing proves the CLI was unmodified. |
| `received_at`, from the app's clock. | `signed_at`, `started_at`, `finished_at`, `observed_at`. These come from the machine's clock, and only the skew window bounds them. |
| The schema and consistency checks passed. | That a command ran at all. |

The app never upgrades an asserted field to verified, and never reads the repo, file or URL a receipt names.

## Storage

**Decision:** v2 keeps v1's single D1 database. `sessions` and `blocked_servers` are unchanged. `github_budget` is dropped, `receipts` is replaced, `keys` is added, and `rate_reservations` gets a generic unit column. **Rejected:** a second store for keys (such as KV), for the same consistency reason v1 gave: a revoked key must stop working on every edge at once.

Migration `0003_v2.sql` (numbered after v1's 0001 and 0002, which are already applied in production):

```sql
DROP TABLE IF EXISTS github_budget;

-- v1 receipts are GitHub verdicts in a different shape; they are not migrated.
DROP TABLE IF EXISTS receipts;

CREATE TABLE keys (
  key_id            TEXT PRIMARY KEY,           -- "ck_" + 26 chars base32
  public_key        TEXT NOT NULL UNIQUE,       -- "ed25519:" + base64url; one binding per key, ever
  server_id         TEXT NOT NULL,
  principal_id      TEXT NOT NULL,
  principal_type    TEXT NOT NULL,
  label             TEXT,
  registered_at     TEXT NOT NULL,              -- RFC 3339 UTC, app clock
  revoked_at        TEXT,
  revoked_reason    TEXT CHECK (revoked_reason IN ('rotated','lost','compromised','operator')),
  compromised_since TEXT
);
CREATE INDEX keys_principal ON keys (server_id, principal_id);

CREATE TABLE receipts (
  id             TEXT PRIMARY KEY,              -- "rcpt_" + 26 chars base32 of SHA-256(JCS(payload))
  server_id      TEXT NOT NULL,
  principal_id   TEXT NOT NULL,
  principal_type TEXT NOT NULL,
  key_id         TEXT NOT NULL REFERENCES keys(key_id),
  kind           TEXT NOT NULL CHECK (kind IN ('run','attest')),
  signed_at      TEXT NOT NULL,                 -- asserted, copied from payload
  received_at    TEXT NOT NULL,                 -- app clock
  expires_at     TEXT NOT NULL,                 -- received_at + 90 days
  envelope_json  TEXT NOT NULL,                 -- the envelope exactly as parsed, re-serialized as JCS
  ledger_json    TEXT NOT NULL                  -- the ledger at insert; key status is joined live on read
);
CREATE INDEX receipts_server_received ON receipts (server_id, received_at);
CREATE INDEX receipts_key_received ON receipts (key_id, received_at);
CREATE INDEX receipts_expires ON receipts (expires_at);

ALTER TABLE rate_reservations RENAME COLUMN claim_count TO units;
-- action is now one of: 'submit', 'register', 'revoke', 'read'
```

`envelope_json` is stored as JCS so that `claim-check verify` on a `get_receipt` result reproduces the signed bytes exactly. Raw stdin, full output, environment values and tokens never reach the Worker, so they cannot be stored.

**Retention:**
- Receipts: 90 days from `received_at`, then hard-deleted. `get_receipt` then returns the same `404` as for an unknown ID.
- Keys: rows are **never deleted**, revoked ones included. A key row is a public key and a binding, a few hundred bytes. Keeping it is what makes "a revoked key can never be registered again" and "a key binds only once" enforceable, and it is what lets `get_receipt` explain a revoked key.
- Sessions: as in v1.
- Rate reservations: deleted once older than one hour, the longest window.
- The CLI's local spool: pending receipts are moved to `rejected/` after 7 days, and rejected files are deleted after 30 days.

The daily scheduled purge from v1 runs these deletions.

## Receipt visibility

**Decision:** carried over unchanged from v1 (`docs/design.md`, `## Receipt visibility`). A receipt is visible only to principals of the Raft server whose session submitted it. Any agent on that server may read it. `get_receipt` runs one query scoped by the session's `server_id`, and an unknown, malformed, expired or other-server ID all get the identical `404 receipt_not_found`. There are still no public share URLs. **Rejected:** public share URLs, for the reason v1 gave: they would make receipts bearer credentials and leak a private server's activity, and in v2 a receipt can also carry output tails and git remotes.

**One change:** a `get_receipt` response now includes the signing key's **current** status (`ledger.key`), so a reader sees a revocation that happened after submission. The envelope also stays verifiable offline: a holder may pass a receipt to anyone, who can check the signature with `claim-check verify`. That is the holder's choice, and the app publishes nothing.

## Rate limits and abuse

**Decision:** v2 keeps v1's sliding windows in `rate_reservations`, with one atomic conditional `INSERT` per request made **before** any signature verification or write. **Rejected:** a token bucket in KV or memory, for v1's reason: it is not consistent across edges.

| Limit | Value |
| --- | --- |
| Request body (all actions) | max **64 KB**. `413 receipt_too_large` on `submit_receipt`, `400 invalid_request` elsewhere |
| Field caps inside a receipt | argv ≤ 128 elements and ≤ 8 KB. Each tail ≤ 2,048 bytes. Strings ≤ 1 KB unless stated otherwise |
| `submit_receipt` per agent | **30 / minute** and **600 / hour** |
| `submit_receipt` per server (all its principals) | **3,000 / hour** |
| `register_key` per agent | **5 / hour** |
| `register_key` per server | **30 / hour** |
| `revoke_key` per agent | **10 / hour** |
| `get_receipt` + `get_session` + `list_keys` per agent | **120 / minute** (v1's read limit) |
| Active keys per principal | **5** (`409 too_many_keys`) |

The `submit_receipt` reservation, in the same single-statement style as v1:

```sql
INSERT INTO rate_reservations (server_id, principal_id, action, units, created_at)
SELECT :server_id, :principal_id, 'submit', 1, :now
WHERE (SELECT COUNT(*) FROM rate_reservations
        WHERE server_id = :server_id AND principal_id = :principal_id
          AND action = 'submit' AND created_at > :now - 60000) < 30
  AND (SELECT COUNT(*) FROM rate_reservations
        WHERE server_id = :server_id AND principal_id = :principal_id
          AND action = 'submit' AND created_at > :now - 3600000) < 600
  AND (SELECT COUNT(*) FROM rate_reservations
        WHERE server_id = :server_id
          AND action = 'submit' AND created_at > :now - 3600000) < 3000;
```

`register_key` uses the same shape with `action = 'register'` and its two caps, `revoke_key` uses `action = 'revoke'`, and reads use `action = 'read'`. The reservation succeeded only if `meta.changes = 1`. Otherwise the response is `429 rate_limited` with `{error, hint}` and a `Retry-After` header taken from the oldest reservation still inside the exhausted window, and **nothing is stored**. The CLI keeps the receipt in its spool. As in v1, a request that fails after its reservation (a bad signature, a schema error, a `500`) is not refunded, so probing the verifier costs budget. A duplicate submission also consumes one reservation.

Other abuse controls: the Worker never fetches anything a receipt names (no repo, file or URL), and its only outbound calls are the Login with Raft calls to Raft's own endpoints during the callback. An operator can add a server to `blocked_servers`, as in v1, or revoke a key directly.

## What a receipt proves and does not prove

**Decision:** every stored receipt carries, in `ledger`, an `acceptance_surface`, `proved`, `not_proved`, `verified` and `asserted`, following the Raft Manual recipe `proof-of-work-receipts`. Here `asserted` plays the role of the recipe's "inferred": it covers everything the app takes on the signer's word. **Rejected:** a single "verified ✅" badge on a receipt, which is the recipe's "unscoped receipt" failure: a reader would take a signed record to prove that the work was correct.

### A `run` receipt

- **Acceptance surface:** the exit status and output of the exact argv in the receipt, run in the recorded git checkout, on the machine holding the registered key.
- **Proves (verified):** the holder of key K, bound to principal P on server S, signed this exact record, and it reached the ledger at `received_at` while K was active.
- **Proves (asserted by the key holder):** that argv ran with HEAD H and dirty flag D, exited with code C, and produced output whose full bytes hash to the recorded digests.
- **Does not prove:**
  - that the CLI was unmodified, or that the command ran at all;
  - that the command checks what the claim is about;
  - that H is pushed, reviewed, merged or deployed, or that a `dirty: true` tree contained anything in particular;
  - that the environment, inputs, network or time matched any other run, or that the result is reproducible;
  - that this was the only attempt. The CLI submits every run, but a lying owner can withhold the red ones;
  - anything after `finished_at`.

### An `attest` receipt

- **Acceptance surface:** the bytes of one file at the recorded path, on the machine holding the key.
- **Proves (verified):** as for `run`, that K's holder signed this record and when it was received.
- **Proves (asserted):** at `observed_at`, the file at `path` had SHA-256 X and size N.
- **Does not prove:** that the file is the output of any particular command or commit; that it is the file that was shipped, uploaded or deployed; or that its contents are correct. A reader holding a copy of the file can recompute the hash and check that it matches. That is the strongest use of an `attest` receipt.

### The proxy trap

A receipt proves the command that ran, **not the claim it is cited for**. "Tests passed" can be "proven" by a `run` receipt that never ran the tests the claim is about:
- `go test ./pkg/unrelated/...` exits 0 while the changed package was never tested.
- `npm test` where the `test` script is `echo ok`, or `make test || true`.
- `pytest -k nothing_matches` or a filter that deselects the relevant tests.
- The right command, run on a `dirty: true` tree where the failing test was edited or deleted, or on a HEAD other than the commit under review.

How v2 counters it, without pretending to solve it: the receipt carries the redacted argv verbatim, `cwd_rel`, `git.head`, `git.dirty` and an output tail, so a reader can check all four of these:
- the argv targets the code the claim names;
- HEAD is the commit under review;
- `dirty` is false;
- the tail shows the expected test count.

A handoff should cite the claim, the `receipt_id`, and one sentence linking them, as the recipe's "tie receipt to the acceptance surface" counter asks. If the claim is about a live surface, such as a deployed page or a merged PR, a local `run` receipt is a proxy, and the live surface needs its own check.

## GitHub adapter (later)

**Decision:** GitHub checks come back later as an **optional adapter** that writes into this same ledger, never through a central token. **Rejected:** reviving v1's shared `GITHUB_TOKEN`. The most likely shape is a new receipt `kind` (for example `observe`) produced by the CLI on the agent's machine, using the agent's own GitHub credentials. It records the endpoint read, the response status and a hash of the fields read, and is signed by the same key. Like every v2 receipt, it is **asserted** by the key holder. The alternative is a per-server GitHub App installation, where each Raft server brings its own installation and the Worker reads with that server's installation token only. That would make some fields app-verified, at the cost of the Worker reading external repos again. Choosing between the two, and reusing v1's claim kinds and verdict rules from its branch, is deferred.

## Open questions

1. **Preflight** (carried from v1 item 1): does the CLI call `login_url` with `GET ?code=…`, which token-endpoint auth method applies, and does the CLI cookie jar honour `Path=/api/agent` and `SameSite=Strict`?
2. **Uninstall** (carried from v1 item 3): does Raft send an uninstall notification, so Claim Check can revoke that server's sessions and keys at once?
3. Does `raft integration env --service claim-check` print a per-agent profile HOME/XDG tree for a manifest that declares no local CLI environment, and in what output format?
4. Does `raft integration invoke --data-file -` forward the JSON object unchanged, and what is the largest body it accepts?
5. Does `raft integration invoke --json` expose the service's HTTP status and `{error, hint}` in a stable field the CLI can parse, so it can tell `401` from `400`?
6. Can a server owner or admin principal be identified from the session, so that admins (not only the bound principal) may revoke a server's keys?
7. Should a `pty` mode be added so children that check for a TTY keep their colour output under `claim-check run`?
8. Should readers get a `list_receipts` action (by key or by principal) so they can see red runs next to green ones?
9. Is Windows support needed in v2, given that file mode `0600` has no direct equivalent there?
10. Should `run` also record a hash of `git diff HEAD` when `dirty` is true, so a reader can tell which uncommitted change was tested?
