// Step 10 of ## Verification: every type, format, length and cap from ## Receipt schema and ## Redaction policy,
// plus the consistency rules. Where docs/design-v2.md is silent, the stricter reading is taken and noted inline.
import { base64urlDecode } from "./crypto";
import { isJsonObject, type JsonObject } from "./http";
import type { JsonValue, NumberIssue } from "./jcs";
import { parseUtcMillis } from "./time";

export interface GitRecord { remote_url: string | null; head: string | null; branch: string | null; dirty: boolean }
export interface StreamRecord { sha256: string; bytes: number; tail: string; tail_truncated: boolean; tail_redactions: number }
export interface RunRecord {
  argv: string[]; argv_redactions: number; cwd_rel: string | null; started_at: string; finished_at: string; duration_ms: number;
  exit: { code: number | null; signal: string | null }; stdout: StreamRecord; stderr: StreamRecord;
}
export interface AttestRecord { path: string; sha256: string; bytes: number; observed_at: string }
export interface ReceiptPayload {
  schema: string; kind: "run" | "attest"; nonce: string; key_id: string; bound_to: { server_id: string; principal_id: string };
  cli: { name: string; version: string; os: string; arch: string }; signed_at: string; git: GitRecord | null;
  run?: RunRecord; attest?: AttestRecord;
}

const MAX_STRING_BYTES = 1024;
const MAX_TAIL_BYTES = 2048;
const MAX_ARGV = 128;
const MAX_ARGV_BYTES = 8192;
const MAX_INTEGER = 2 ** 53;
const NONCE_BYTES = 16;
const KEY_ID = /^ck_[a-z2-7]{26}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_HEAD = /^[0-9a-f]{40}$/;
// Userinfo in the authority of a scheme:// URL.
const URL_USERINFO = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*@/;
// The tail sanitizer strips control characters other than \n and \t; C1 controls count as control characters too.
const TAIL_CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/;

const PAYLOAD_FIELDS = ["schema", "kind", "nonce", "key_id", "bound_to", "cli", "signed_at", "git"] as const;
const RUN_FIELDS = ["argv", "argv_redactions", "cwd_rel", "started_at", "finished_at", "duration_ms", "exit", "stdout", "stderr"] as const;
const STREAM_FIELDS = ["sha256", "bytes", "tail", "tail_truncated", "tail_redactions"] as const;
const ATTEST_FIELDS = ["path", "sha256", "bytes", "observed_at"] as const;

class Invalid extends Error {}

const utf8Length = (text: string) => new TextEncoder().encode(text).byteLength;
const member = (field: string, name: string) => (field === "" ? name : `${field}.${name}`);
/** Throws the schema_invalid hint, which names the field (`payload` itself when `field` is empty). */
const fail = (field: string, rule: string): never => { throw new Invalid(`${field === "" ? "payload" : `payload.${field}`} ${rule}.`); };

/** An object with exactly `fields`, every one present. Unknown members are rejected (stricter; the doc lists the fields only). */
function record(value: JsonValue | undefined, field: string, fields: readonly string[]): JsonObject {
  if (!isJsonObject(value)) return fail(field, "must be an object");
  for (const name of fields) if (!(name in value)) fail(member(field, name), "is required");
  const unknown = Object.keys(value).find((name) => !fields.includes(name));
  if (unknown !== undefined) fail(field, `has an unknown field ${JSON.stringify(unknown).slice(0, 64)}`);
  return value;
}

/** A string of at most `maxBytes` UTF-8 bytes. Empty strings are refused unless `allowEmpty` (the doc is silent; stricter). */
function text(value: JsonValue | undefined, field: string, { maxBytes = MAX_STRING_BYTES, allowEmpty = false } = {}): string {
  if (typeof value !== "string") return fail(field, "must be a string");
  if (!allowEmpty && value === "") fail(field, "must not be empty");
  if (utf8Length(value) > maxBytes) fail(field, `must be at most ${maxBytes} bytes`);
  return value;
}

const nullableText = (value: JsonValue | undefined, field: string): string | null => (value === null ? null : text(value, field));

function integer(value: JsonValue | undefined, field: string, min: number, max = MAX_INTEGER): number {
  if (typeof value !== "number" || !Number.isInteger(value)) return fail(field, "must be an integer");
  if (value < min || value > max) fail(field, `must be from ${min} to ${max}`);
  return value;
}

function boolean(value: JsonValue | undefined, field: string): boolean {
  if (typeof value !== "boolean") return fail(field, "must be a boolean");
  return value;
}

function time(value: JsonValue | undefined, field: string): number {
  const ms = parseUtcMillis(text(value, field));
  return ms === null ? fail(field, "must be an RFC 3339 UTC time with milliseconds, like 2026-10-06T09:00:03.120Z") : ms;
}

function sha256(value: JsonValue | undefined, field: string): string {
  const digest = text(value, field);
  return SHA256.test(digest) ? digest : fail(field, "must be sha256: followed by 64 lowercase hex characters");
}

/** A path that stays inside the repository: not starting with / or \, and no ".." segment (stricter; the doc only says "relative"). */
function relativePath(value: JsonValue | undefined, field: string): string {
  const path = text(value, field);
  if (path.startsWith("/") || path.startsWith("\\") || path.split("/").includes("..")) fail(field, "must be relative to the repository root without ..");
  return path;
}

function validateGit(value: JsonValue | undefined): GitRecord | null {
  if (value === null) return null;
  const git = record(value, "git", ["remote_url", "head", "branch", "dirty"]);
  const remoteUrl = nullableText(git.remote_url, "git.remote_url");
  // The CLI removes userinfo from origin's URL; a scheme URL that still carries user@ or user:password@ is refused.
  if (remoteUrl !== null && URL_USERINFO.test(remoteUrl)) fail("git.remote_url", "must not contain userinfo");
  const head = nullableText(git.head, "git.head");
  // "the full 40-hex SHA": lowercase, as git prints it (stricter; the doc does not name the case).
  if (head !== null && !GIT_HEAD.test(head)) fail("git.head", "must be 40 lowercase hex characters or null");
  nullableText(git.branch, "git.branch");
  boolean(git.dirty, "git.dirty");
  return git as unknown as GitRecord;
}

function validateStream(value: JsonValue | undefined, field: string): void {
  const stream = record(value, field, STREAM_FIELDS);
  sha256(stream.sha256, `${field}.sha256`);
  const bytes = integer(stream.bytes, `${field}.bytes`, 0);
  const tail = text(stream.tail, `${field}.tail`, { maxBytes: MAX_TAIL_BYTES, allowEmpty: true });
  if (TAIL_CONTROL.test(tail)) fail(`${field}.tail`, "must not contain control characters other than newline and tab");
  const truncated = boolean(stream.tail_truncated, `${field}.tail_truncated`);
  const redactions = integer(stream.tail_redactions, `${field}.tail_redactions`, 0);
  // An empty stream has nothing to show, drop or mask (stricter consistency; the doc does not state it).
  if (bytes === 0 && (tail !== "" || truncated || redactions !== 0)) fail(field, "must have an empty, untruncated, unredacted tail when bytes is 0");
}

function validateRun(value: JsonValue | undefined, git: GitRecord | null, signedAt: number): void {
  const run = record(value, "run", RUN_FIELDS);
  if (!Array.isArray(run.argv) || run.argv.length < 1 || run.argv.length > MAX_ARGV) fail("run.argv", `must be an array of 1 to ${MAX_ARGV} strings`);
  const argv = run.argv as JsonValue[];
  let argvBytes = 0;
  argv.forEach((element, index) => {
    // Each element is also held to the general 1 KB string cap, and the command itself must be non-empty (stricter).
    argvBytes += utf8Length(text(element, `run.argv[${index}]`, { allowEmpty: index > 0 }));
  });
  if (argvBytes > MAX_ARGV_BYTES) fail("run.argv", `must be at most ${MAX_ARGV_BYTES} bytes in total`);
  // "The number of argv elements that were masked", so never more than argv has (stricter).
  integer(run.argv_redactions, "run.argv_redactions", 0, argv.length);
  // cwd_rel is null outside a repository and a relative path inside one; both directions are enforced (stricter).
  if (git === null) {
    if (run.cwd_rel !== null) fail("run.cwd_rel", "must be null when git is null");
  } else {
    relativePath(run.cwd_rel, "run.cwd_rel");
  }
  const startedAt = time(run.started_at, "run.started_at");
  const finishedAt = time(run.finished_at, "run.finished_at");
  if (startedAt > finishedAt) fail("run.started_at", "must not be after run.finished_at");
  if (finishedAt > signedAt) fail("run.finished_at", "must not be after signed_at");
  integer(run.duration_ms, "run.duration_ms", 0);
  const exit = record(run.exit, "run.exit", ["code", "signal"]);
  // An exit status is 0 to 255 (stricter; the doc says only "integer"). The signal name has no stated format.
  if (exit.code !== null) integer(exit.code, "run.exit.code", 0, 255);
  if (exit.signal !== null) text(exit.signal, "run.exit.signal");
  if ((exit.code === null) === (exit.signal === null)) fail("run.exit", "must have exactly one of code and signal non-null");
  validateStream(run.stdout, "run.stdout");
  validateStream(run.stderr, "run.stderr");
}

function validateAttest(value: JsonValue | undefined, git: GitRecord | null, signedAt: number): void {
  const attest = record(value, "attest", ATTEST_FIELDS);
  const path = relativePath(attest.path, "attest.path");
  // Outside a repository the path is the file's base name (stricter: enforced).
  if (git === null && path.includes("/")) fail("attest.path", "must be a base name when git is null");
  sha256(attest.sha256, "attest.sha256");
  integer(attest.bytes, "attest.bytes", 0);
  // The file is read before signing, as run.finished_at is (stricter; the doc orders only run's times).
  if (time(attest.observed_at, "attest.observed_at") > signedAt) fail("attest.observed_at", "must not be after signed_at");
}

/**
 * Validates a payload that already passed steps 6 to 9 (schema and kind known). `numberIssues` are the
 * number-domain violations the parser recorded for the whole body. Returns the typed payload, or the hint.
 */
export function validatePayload(payload: JsonObject, numberIssues: readonly NumberIssue[]): { payload: ReceiptPayload; signedAt: number } | string {
  try {
    // No floats: a number written with a fraction or exponent is refused even when its value is integral (1.0, 1e3).
    const issue = numberIssues.find((found) => found.path.startsWith("receipt.payload."));
    if (issue) fail(issue.path.slice("receipt.payload.".length).slice(0, 200), "must be an integer within +/-2^53, without fraction, exponent or -0");

    const kind = payload.kind as "run" | "attest";
    const other = kind === "run" ? "attest" : "run";
    if (!(kind in payload) || other in payload) fail(kind, `must be present, and ${other} absent, when kind is ${kind}`);
    record(payload, "", [...PAYLOAD_FIELDS, kind]);

    const nonce = text(payload.nonce, "nonce");
    let nonceBytes = 0;
    try { nonceBytes = base64urlDecode(nonce).length; } catch { fail("nonce", "must be unpadded base64url"); }
    if (nonceBytes !== NONCE_BYTES) fail("nonce", `must encode ${NONCE_BYTES} bytes`);
    if (!KEY_ID.test(text(payload.key_id, "key_id"))) fail("key_id", "must be ck_ followed by 26 lowercase base32 characters");
    const boundTo = record(payload.bound_to, "bound_to", ["server_id", "principal_id"]);
    text(boundTo.server_id, "bound_to.server_id");
    text(boundTo.principal_id, "bound_to.principal_id");
    const cli = record(payload.cli, "cli", ["name", "version", "os", "arch"]);
    if (cli.name !== "claim-check") fail("cli.name", "must be claim-check");
    for (const field of ["version", "os", "arch"]) text(cli[field], `cli.${field}`);
    const signedAt = time(payload.signed_at, "signed_at");
    const git = validateGit(payload.git);
    if (kind === "run") validateRun(payload.run, git, signedAt);
    else validateAttest(payload.attest, git, signedAt);
    return { payload: payload as unknown as ReceiptPayload, signedAt };
  } catch (cause) {
    if (cause instanceof Invalid) return cause.message;
    throw cause;
  }
}
