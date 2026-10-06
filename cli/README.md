# claim-check CLI

`claim-check` runs a command (or hashes a file) on the agent's own machine, records what happened, signs the record with a per-machine Ed25519 key, and submits it to the Claim Check app through `raft integration invoke`. The contract is [docs/design-v2.md](../docs/design-v2.md). This module is standard-library Go only.

## Install and build

The CLI needs Go 1.25 to build and has no dependencies outside the standard library. At run time it needs the Raft CLI (`raft`, with Agent Login) on `PATH`, and `git` for the git fields.

```bash
make -C cli test      # gofmt check, go vet, go test
make -C cli release   # static binaries (CGO_ENABLED=0) in cli/dist/ plus cli/dist/SHA256SUMS
go -C cli build -o claim-check .   # one binary for this machine
```

`make release` builds `claim-check_{linux,darwin}_{amd64,arm64}` and writes `SHA256SUMS` with `sha256sum`, or `shasum -a 256` where `sha256sum` is missing (macOS). Set `VERSION=...` to stamp `cli.version`; the default is `2.0.0-dev`. `cli/dist/` is ignored by git. The repository has no CI workflow and no published release.

First use on a machine, for each agent profile:

```bash
claim-check key init
claim-check key register --label laptop
claim-check run -- go test ./...
```

## Commands

Every command except `verify` first runs `raft auth whoami`. If that fails, the command exits `78` with a hint to run `raft integration login --service <service>`.

| Command | What it does | Exit codes |
| --- | --- | --- |
| `claim-check run [--require-receipt] [--quiet] [--redact-arg N]... -- <cmd> [args...]` | Runs `<cmd>` with stdin, environment, stdout and stderr passed through. Signs a receipt, writes it to the spool, submits it, and prints one `claim-check:` line on stderr after the child exits. | The child's code, or `128+N` if signal N killed it. Before the child starts: `64` usage, `78` no usable or unregistered key, `127` not found, `126` cannot execute. With `--require-receipt`, `75` if the child exited `0` but the receipt was not stored. |
| `claim-check attest --file <path>` | Records the SHA-256 and size of one regular file, then signs and submits. | `0` stored, `75` kept in the spool, `1` refused (directory, device, outside symlink, app rejection), `64`, `78` |
| `claim-check key init` | Creates this profile's key. Refuses if one exists. | `0`, `1` exists, `78` |
| `claim-check key register [--label <text>]` | `get_session`, then a proof-of-possession statement sent to `register_key`. Stores the binding in `key.json`. | `0`, `1` refused, `75` retry, `78` |
| `claim-check key show` | Prints `key_id`, the public key, the binding and the key file path. Never prints the private key. | `0`, `78` |
| `claim-check key list` | `list_keys`, as a table. `*` marks this profile's key. | `0`, `1`, `75`, `78` |
| `claim-check key revoke [--key-id <id>] --reason rotated\|lost\|compromised [--compromised-since <time>]` | `revoke_key`. Defaults to this profile's key and does not need the private key. | `0`, `1`, `64`, `75`, `78` |
| `claim-check key rotate [--force]` | `flush`. Then it refuses, changing nothing, if receipts signed by the old key are still pending (unless `--force`). Otherwise it runs `key init`, `key register`, then `key revoke --reason rotated` for the old key and deletes the old key file. | `0`, `75` refused while pending, `1`, `78` |
| `claim-check flush` | Moves pending receipts older than 7 days to `rejected/`, then resubmits the rest oldest first. Stops at the first `401` or `429`. Deletes rejected files older than 30 days. | `0` nothing pending, `75` some still pending, `78` |
| `claim-check verify <receipt.json\|-> [--public-key <ed25519:...>]` | Offline. Strict parse, JCS re-encoding, the `receipt_id` check and the signature check. Never calls Raft. | `0` valid, `1` invalid, `64` |

**Service id.** `--service <id>` (on any command, or before the command) takes precedence, then `$CLAIM_CHECK_SERVICE`, then `claim-check`. Every action runs `raft integration invoke <service> <action> --data-file - --json`, with the JSON body on stdin and never in argv.

**Submit outcomes** (the design's `### Submitting` table):

| Outcome | Spool |
| --- | --- |
| `200`/`201` whose `receipt_id` equals the local ID | removed |
| `raft` missing or no `integration` command, not logged in, `401` | kept, with a hint. `flush` stops |
| timeout, unparseable invoke output, `5xx`, any other status, or `200`/`201` without the matching `receipt_id` | kept. `flush` retries |
| `429` | kept. `flush` stops |
| `400`, `403`, `409`, `413` with a known `submit_receipt` error code (`invalid_request`, `schema_unsupported`, `binding_mismatch`, `key_not_registered`, `key_revoked`, `bad_signature`, `schema_invalid`, `clock_skew`, `receipt_too_old`, `receipt_too_large`) | moved to `spool/rejected/` with the app's `{error, hint}`. Never retried |
| `400`, `403`, `409`, `413` with no parseable `{error}` body or an unknown code (such as a Raft-side `INTEGRATION_INVOKE_FAILED`) | kept, outcome unknown. `flush` retries |

## Files

For a Raft server `S` and agent `A` from `raft auth whoami` (see decision 1):

| File | Path | Mode |
| --- | --- | --- |
| Private key (raw 32-byte seed) | `${XDG_CONFIG_HOME:-$HOME/.config}/claim-check/S/A/key/ed25519` | `0600` |
| Key metadata | `${XDG_CONFIG_HOME:-$HOME/.config}/claim-check/S/A/key/key.json` | `0600` |
| Pending spool | `${XDG_STATE_HOME:-$HOME/.local/state}/claim-check/S/A/spool/<receipt_id>.json` | `0600` |
| Rejected spool | `${XDG_STATE_HOME:-$HOME/.local/state}/claim-check/S/A/spool/rejected/<receipt_id>.json` | `0600` |

Every directory from `claim-check/` down is `0700`. A pending file holds exactly the `submit_receipt` body, `{"receipt": {"payload": ..., "signature": ...}}`, as JCS. A rejected file adds `"rejection": {"status", "error", "hint", "rejected_at"}`.

## Layout

| Package | Purpose |
| --- | --- |
| `main.go` | The `claim-check` entry point. |
| `internal/app` | Commands, flags, exit codes, submit and spool policy. |
| `internal/raft` | The only Raft boundary: the `Raft` interface (`Whoami`, `Invoke`) and its `raft` subprocess implementation (30-second timeout). |
| `internal/redact` | The redaction policy: tail and argv masks. |
| `internal/gitinfo` | `payload.git` and `cwd_rel`, read with the `git` CLI. |
| `internal/spool` | Pending and rejected receipt files. |
| `internal/jcs` | RFC 8785 JSON Canonicalization Scheme (encoder) and a strict JSON parser. |
| `internal/receipt` | Wire format: encodings, `receipt_id` and `key_id`, typed payloads and builders, envelope sign and verify. |
| `internal/keystore` | Key and spool locations per (server, agent), key files, modes. |
| `internal/vectors` | Builds the shared test vectors. Its test checks `spec/vectors/` against the code. |
| `cmd/genvectors` | Writes `spec/vectors/` at the repository root. |

Tests never run the real `raft`: the command tests use a fake `raft.Raft`, and the `internal/raft` tests run a stand-in shell script.

## Test vectors

`spec/vectors/` holds fixed vectors that the CLI and the Worker both test against. The files are `key.json`, `receipt-run.json`, `receipt-attest.json`, `registration.json` and `jcs-cases.json`. Regenerate them with:

```bash
go -C cli run ./cmd/genvectors
```

The output is deterministic: a fixed **TEST ONLY** seed, fixed nonces, fixed times. `go -C cli test ./...` fails if the files on disk differ from what the generator produces. It also re-derives every value in them independently: public key, key ID, JCS, SHA-256, receipt ID, the signature (which must verify and must equal the deterministic Ed25519 signature) and every JCS case.

## Decisions not in the design

1. **Key location.** This replaces the design's `raft integration env` paragraph in `### Where the key lives`. The preflight on 2026-10-06 showed that `raft integration env --service claim-check` prints an empty env and no profile folder for this app, so the CLI picks the location itself:
   - config dir = `$XDG_CONFIG_HOME` (else `$HOME/.config`) + `/claim-check/<server_id>/<agent_id>/`
   - state dir = `$XDG_STATE_HOME` (else `$HOME/.local/state`) + `/claim-check/<server_id>/<agent_id>/`

   Inside them, the design table's names and modes apply: `key/ed25519` (raw 32-byte seed, `0600`), `key/key.json` (`0600`), `spool/<receipt_id>.json` and `spool/rejected/` (files `0600`), and every directory `0700`. `server_id` and `agent_id` come from the Raft CLI's identity (whoami). If whoami fails, every key command, `run`, `attest` and `flush` exit `78` with a hint to run `raft integration login --service claim-check`. The path derivation is a pure function, `keystore.Resolve(env, serverID, agentID)`, so two agents on one OS user get two directories.
2. **XDG edge cases.** An XDG variable that is empty or relative is ignored, as the XDG spec says, and `$HOME` is used. If the fallback `$HOME` is also unset or relative, resolution fails (`keystore.ErrNoHome`). The command layer maps that to exit `78`.
3. **IDs as path segments.** `server_id` and `agent_id` must be one path segment: not empty, not starting with `.`, and with no `/`, `\` or NUL. Otherwise the CLI refuses (`keystore.ErrBadID`) and does not sanitize.
4. **Directory modes.** The CLI creates its directories `0700` and also tightens to `0700` any it owns that already exist (`claim-check/` and everything below it). It does not change directories above `claim-check/`.
5. **Key file checks.** The "no group or other permission" check (as OpenSSH does it) applies to both `key/ed25519` and `key/key.json`. Both are opened with `O_NOFOLLOW` and checked on the open descriptor. A symlink, a non-regular file, or a seed that is not exactly 32 bytes is refused. `key init` writes the seed with `O_CREAT|O_EXCL`. `key.json` is rewritten atomically (temporary file in the same directory, then rename).
6. **`key.json` format.** `{"key_id": "ck_…", "public_key": "ed25519:…", "bound_to": {"server_id", "principal_id"} | null}`. `bound_to` is `null` until `key register` succeeds, and it uses the same name and shape as `payload.bound_to`.
7. **Nonce encoding.** `nonce` (both receipt and registration statement) is 16 bytes from `crypto/rand` as unpadded base64url, 22 characters, the same base64url form as keys and signatures.
8. **Registration `label`.** It is always present in the statement: a string with `--label`, otherwise `null`.
9. **Integer range.** The parser and encoder accept integers in **[-2^53, 2^53] inclusive** (the design's "within ±2^53"), stored as `int64`. Integers are written as plain shortest decimal.
10. **Number syntax.** Any number with a fraction or exponent is rejected, even if its value is integral (`1.0`, `1e3`). `-0` is accepted and canonicalizes to `0`, as JavaScript JCS does. This is in `jcs-cases.json`.
11. **Strict parser details.** The parser rejects invalid UTF-8, a byte-order mark, trailing data, unpaired UTF-16 surrogates in `\u` escapes, and nesting deeper than 64. Duplicate keys are compared after unescaping, so `"a"` and `"a"` are duplicates. Only JSON whitespace (space, tab, LF, CR) is allowed between tokens.
12. **Envelope verification.** `signature.alg` must be `ed25519`. `signature.value` and public keys must be canonical unpadded base64url (padding and non-zero trailing bits are refused) of exactly 64 or 32 bytes. Go's `ed25519.Verify` rejects a non-canonical `S`. `signature.key_id` and `payload.key_id` must both equal `key_id` of the verifying key. `Sign` refuses a payload whose `key_id` is not the signer's.
13. **Envelope serialization.** The CLI serializes envelopes as JCS (`Envelope.MarshalJSON`), so a spooled or printed envelope carries the signed bytes verbatim. `verify` accepts a bare envelope, `{"receipt": envelope}`, `{"registration": envelope}` or a stored receipt `{"receipt_id", "envelope", ...}` (`receipt.FindEnvelope`), and always recomputes JCS from the parsed payload.
14. **Timestamps.** Exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` (24 characters). Finer precision is truncated, not rounded. `receipt.ParseTime` accepts no other offset or precision.
15. **Pre-signing validation.** Before signing, the CLI checks schema and kind, `run` xor `attest`, `exit.code` xor `exit.signal`, argv 1..128 elements and at most 8 KB, tails at most 2,048 bytes, and time formats. The Worker re-checks all of it.
16. **Test vectors.** The vectors live in `spec/vectors/` at the repository root, so the Worker can read them without depending on `cli/`. The test seed is the ASCII text `claim-check-v2 TEST ONLY seed!!!`, and `key.json` carries a `comment` field that labels it TEST ONLY. `registration.json` has no `receipt_id`, because the design defines receipt IDs only for receipts.
17. **Raft calls.** All traffic goes through `raft.Raft`, which has two methods. `Whoami` runs `raft auth whoami` and reads `data.server.id` and `data.agent.id`. `Invoke` runs `raft integration invoke <service> <action> --data-file - --json` with the body on stdin. Actions without parameters (`get_session`, `list_keys`) send `{}`, which differs from the design's `get_session --json` without `--data-file`. The output shapes were confirmed 2026-10-06. Success is `{"ok": true, "data": {"status": int, "result": ...}}`: HTTP status = `data.status`, body = `data.result`. Failure is `{"ok": false, "error": {"code": "INTEGRATION_INVOKE_FAILED", "message": "... (HTTP 404); response body: {...}", ...}}`: the status and the app's body are embedded as text in `error.message`, so HTTP status = the `HTTP nnn` in the message and body = the text after `response body: `. Output is parsed even when `raft` exits non-zero. Anything else, including another `error.code` or a message without `HTTP nnn`, means the outcome is unknown.
18. **Service id.** The design hard-codes `claim-check`. The CLI takes `--service <id>` (a command flag, or a global flag before the command), then `$CLAIM_CHECK_SERVICE`, then `claim-check`. A service id that starts with `-` or contains whitespace is a usage error, so it cannot become a `raft` flag. Hints name the resolved service.
19. **Classifying raft failures.** `raft` missing from `PATH` (or a missing binary) and output saying "unknown command" map to the "`raft` not on PATH" row. "Not logged in" or "not authenticated" maps to the "not logged in" row. A 30-second timeout and anything else unrecognised mean "outcome unknown". In every one of these cases the receipt stays in the spool.
20. **Retry-After.** The invoke output carries no response headers, so the CLI cannot read `Retry-After`. `flush` stops at the first `429`, and the next `flush` is the retry. Nothing sleeps.
21. **Other statuses.** `200`/`201` without the matching `receipt_id`, `404`, `3xx` and any other unlisted status keep the receipt (outcome unknown). Besides `401` and `429`, `flush` also stops when `raft` is missing or not logged in, because every later receipt would fail the same way.
22. **Exit codes outside `run`.** `0` success; `1` a permanent failure (app refusal, verify failure, refused attest input, existing key); `64` usage; `75` try again later (receipt kept in the spool, `flush` left receipts pending, `rotate` refused while pending, `429`/`5xx`/unknown outcome); `78` no usable key, whoami failure, `raft` missing, not logged in, or `401`. `attest` exits `0` when stored, `75` when kept and `1` when rejected.
23. **`run` checks before the child starts.** The redacted argv and the other fields known up front are validated as a provisional payload: argv 1 to 128 elements and at most 8 KB, strings at most 1 KB. A command whose receipt could never be valid exits `64` without running. `--redact-arg N` indexes the recorded argv, so `0` is the command name. An index past the end is a usage error. The mask for `--redact-arg` is `[REDACTED:redact_arg]`.
24. **argv masks.** A flag is `-name` or `--name`. In `--name value` form the next element is masked in full, whatever it is. A flag at the end of argv masks nothing. `argv_redactions` counts masked elements, not matches. The text rules apply to every element that the flag rules leave alone.
25. **Tail masks.** Matches of different rules that overlap merge into one mask named after the higher-priority rule (in the order of the design's table), so nothing either rule matched is left visible. The 2,048-byte cut never splits a marker: a marker that straddles the cut is dropped whole. `tail_redactions` counts the masks inside the kept tail. When the scan window starts mid-character after dropped output, the partial character is skipped. A private-key footer whose header is outside the window is masked from the window's start. Control characters that are removed include `\r`, DEL and C1. The `known_token` regex list is in `internal/redact/redact.go`.
26. **Signals and closed outputs.** `run.exit.signal` uses names like `SIGTERM` (`SIG<n>` for unnamed signals). `run` catches `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` and passes them on to the child, with one exception so that Ctrl-C arrives once: `SIGINT` is not forwarded when the child is in the CLI's process group and that group is the controlling terminal's foreground group (read with `TIOCGPGRP` on `/dev/tty`), because the terminal has already sent it to the child. The CLI still catches it, so it is not killed before the receipt is written. If there is no controlling terminal or a group cannot be read, `SIGINT` is forwarded. The other three are always forwarded, even when the terminal already delivered them to the child's process group. While the child runs and until `run` returns, the CLI catches `SIGPIPE` (it does not ignore it, because an ignored disposition would survive `exec` and change the child). A write to the CLI's closed stdout or stderr then fails with `EPIPE` instead of killing the CLI. Copying stops, the pipe to the child is closed, and the child gets `SIGPIPE` on its next write, as in a shell pipeline. The receipt records `exit.signal: "SIGPIPE"` and hashes the bytes the CLI saw, it is spooled and submitted as usual, and `run` exits `141` (the 128+N rule applied to the child). Write errors on the final `claim-check:` line are ignored.
27. **Git fields.** `remote_url` comes from `git remote get-url origin`. Userinfo is removed only from `scheme://` URLs; an scp-like `git@host:path` has no password part and is kept. `dirty` uses `git status --porcelain --untracked-files=normal`, and it is `true` if status cannot be read. Without `git`, or outside a repository, `git` is `null`. Git runs with `GIT_OPTIONAL_LOCKS=0`, so the CLI never writes to the index. For `attest`, the git fields describe the repository that contains the file.
28. **`attest` paths.** A symlink's target must lie inside the file's repository, or inside the working directory when the file is not in a repository. A dangling symlink is refused. The recorded path is the name as given (the link's own name), relative to the repository root. The file is opened with `O_NONBLOCK` and checked on the descriptor, so a FIFO cannot hang the CLI.
29. **Spool details.** "Oldest first" means by `payload.signed_at`, with ties broken by receipt ID. A receipt is expired when it was signed more than 7 days before the CLI's clock. It is moved with `rejection.status` `0` and `error` `receipt_too_old`. An unreadable pending file is moved to `rejected/` unchanged. The 30-day deletion uses the rejected file's mtime, set when the file is moved, and runs at the start of every `flush`.
30. **Registration and rotation.** The binding is taken from `get_session` and is not compared with whoami's IDs. `rotate` renames the old key files to `*.old`, creates and registers the new key, and restores the old files if registration fails. It deletes the old files once the new key is registered, even if the revocation then fails. In that case it prints the exact `key revoke --key-id ... --reason rotated` command and exits non-zero. The new key's label is `null`.
31. **Revoking the local key.** When `key revoke` revokes this profile's own key, the CLI deletes the local `ed25519` and `key.json`, because a revoked key can never be used or registered again, and `key init` would otherwise refuse. `--compromised-since` accepts any RFC 3339 time and is sent as UTC with milliseconds.
32. **`verify` key source.** `--public-key` wins. A registration statement is checked against its own `public_key`. A stored receipt without `--public-key` is checked against `ledger.key.public_key`, with a warning that the app supplied it. Otherwise `--public-key` is required (exit `64`). `verify -` reads stdin. Beyond `schema`, `verify` does not re-run the Worker's field checks.
33. **String caps.** "Strings ≤ 1 KB unless stated otherwise" is enforced before signing on `cli.version`, `cli.os`, `cli.arch`, the git strings, `run.cwd_rel` and `attest.path`. argv elements fall under argv's own 8 KB cap.
