import type { Env } from "./env";

export type Verdict = "confirmed" | "contradicted" | "cant_check";
export interface ReadRecord { method: "GET"; endpoint: string; status: number }
export interface Fact { fact: string; value: unknown; from: string }
export interface Inference { statement: string; rule: string }
export interface ClaimResult {
  index: number; claim: unknown; verdict: Verdict; symbol: string; reason: string | null;
  retry_after_seconds: number | null; checked_at: string;
  source: { system: "github"; reads: ReadRecord[] };
  acceptance_surface: string; proved: string[]; not_proved: string[];
  verified: Fact[]; inferred: Inference[];
}

type Kind = "pr_merged" | "pr_state" | "ci_status" | "commit_on_branch" | "issue_closed" | "tag_exists" | "release_published";
type Checked = { result: ClaimResult; rateLimited?: number };
const ownerRepo = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,37}[A-Za-z0-9])?$/;
const shaPattern = /^[a-fA-F0-9]{40}$/;
const refPattern = /^(?!\/)(?!.*\.\.)(?!.*\.$)(?!.*\.lock(?:\/|$))(?!.*(?:^|\/)\.)(?!.*(?:^|\/)\.\.)[^\x00-\x20\x7f~^:?*\[\\]+$/;
const base = (owner: string, repo: string) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
const headers = (env: Env) => ({ Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" });

/** Build only allowlisted GitHub API URLs. Pagination URLs are reduced to path + query first. */
export async function githubFetch(env: Env, path: string): Promise<Response> {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) throw new Error("Invalid GitHub API path");
  const url = new URL(path, "https://api.github.com");
  if (url.origin !== "https://api.github.com" || url.username || url.password || url.hash ||
      !(url.pathname === "/rate_limit" || /^\/repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/|$)/.test(url.pathname))) {
    throw new Error("GitHub API URL is outside the allowed host and paths");
  }
  return fetch(url, { headers: headers(env), redirect: "manual", signal: AbortSignal.timeout(10_000) });
}

function invalidReason(claim: any): string | undefined {
  if (!claim || typeof claim !== "object" || Array.isArray(claim)) return "invalid_claim";
  if (typeof claim.kind !== "string" || !["pr_merged", "pr_state", "ci_status", "commit_on_branch", "issue_closed", "tag_exists", "release_published"].includes(claim.kind)) return "unsupported_claim_kind";
  if (typeof claim.owner !== "string" || !ownerRepo.test(claim.owner) || typeof claim.repo !== "string" || !ownerRepo.test(claim.repo)) return "invalid_claim";
  if (claim.statement !== undefined && (typeof claim.statement !== "string" || claim.statement.length > 500)) return "invalid_claim";
  const positive = Number.isSafeInteger(claim.number) && claim.number > 0;
  if (["pr_merged", "pr_state", "issue_closed"].includes(claim.kind) && !positive) return "invalid_claim";
  if (claim.kind === "pr_state" && !["open", "closed_unmerged", "merged"].includes(claim.expected_state)) return "invalid_claim";
  if (claim.kind === "ci_status" && (!shaPattern.test(claim.sha) || !["success", "failure"].includes(claim.expected_conclusion) || (claim.check_names !== undefined && (!Array.isArray(claim.check_names) || claim.check_names.some((x: unknown) => typeof x !== "string" || !x || x.length > 200))))) return "invalid_claim";
  if (claim.kind === "commit_on_branch" && (!shaPattern.test(claim.sha) || typeof claim.branch !== "string" || !refPattern.test(claim.branch))) return "invalid_claim";
  if (["tag_exists", "release_published"].includes(claim.kind) && (typeof claim.tag !== "string" || !refPattern.test(claim.tag))) return "invalid_claim";
  if (claim.kind === "tag_exists" && claim.sha !== undefined && !shaPattern.test(claim.sha)) return "invalid_claim";
  return undefined;
}

function shell(index: number, claim: unknown, reason: string, checkedAt: string, reads: ReadRecord[] = [], retry: number | null = null): ClaimResult {
  const c: any = claim || {};
  const kind = typeof c.kind === "string" ? c.kind : "claim";
  return { index, claim, verdict: "cant_check", symbol: "⚠️", reason, retry_after_seconds: retry, checked_at: checkedAt,
    source: { system: "github", reads }, acceptance_surface: `GitHub ${kind} for ${String(c.owner ?? "")}/${String(c.repo ?? "")}`,
    proved: [], not_proved: [], verified: [], inferred: [] };
}

function reasonResult(index: number, claim: any, reason: string, reads: ReadRecord[], checkedAt: string, retry: number | null = null): Checked {
  return { result: shell(index, claim, reason, checkedAt, reads, retry) };
}

function retrySeconds(response: Response): number {
  const retry = Number(response.headers.get("Retry-After"));
  if (Number.isFinite(retry) && retry > 0) return Math.ceil(retry);
  const reset = Number(response.headers.get("x-ratelimit-reset"));
  return Number.isFinite(reset) ? Math.max(1, Math.ceil(reset - Date.now() / 1000)) : 60;
}
function isRateLimited(response: Response): boolean {
  return response.status === 429 || (response.status === 403 && (response.headers.has("Retry-After") || response.headers.get("x-ratelimit-remaining") === "0"));
}

export async function checkClaim(env: Env, index: number, claim: any, repoRead: (repoPath: string) => Promise<{ response: Response; data?: any }>, blocked?: number, observe?: (response: Response) => void): Promise<Checked> {
  const checkedAt = new Date().toISOString();
  const validation = invalidReason(claim);
  if (validation) return reasonResult(index, claim, validation, [], checkedAt);
  const root = base(claim.owner, claim.repo), reads: ReadRecord[] = [];
  const read = async (path: string): Promise<{ response: Response; data?: any }> => {
    let response: Response;
    let data: any;
    try {
      const res = await githubFetch(env, path);
      response = res;
      observe?.(response);
      reads.push({ method: "GET", endpoint: path, status: response.status });
      if (response.status >= 200 && response.status < 300) { try { data = await response.json(); } catch { /* handled as unavailable */ } }
      return { response, data };
    } catch {
      response = new Response(null, { status: 599 });
      reads.push({ method: "GET", endpoint: path, status: 599 });
      return { response };
    }
  };
  const finish = (verdict: Verdict, reason: string | null, surface: string, proved: string[], notProved: string[], verified: Fact[], inferred: Inference[] = [], retry: number | null = null): Checked => ({
    result: { index, claim, verdict, symbol: verdict === "confirmed" ? "✅" : verdict === "contradicted" ? "❌" : "⚠️", reason, retry_after_seconds: retry, checked_at: checkedAt, source: { system: "github", reads }, acceptance_surface: surface, proved, not_proved: notProved, verified, inferred },
    rateLimited: reason === "github_rate_limited" ? retry ?? 60 : undefined,
  });
  if (blocked !== undefined) return reasonResult(index, claim, "github_rate_limited", [], checkedAt, blocked);
  const repoResult = await repoRead(root);
  reads.push({ method: "GET", endpoint: root, status: repoResult.response.status });
  const rs = repoResult.response.status;
  if (isRateLimited(repoResult.response)) return finish("cant_check", "github_rate_limited", `GitHub repository ${claim.owner}/${claim.repo}`, [], [], [], [], retrySeconds(repoResult.response));
  if (rs === 404) return finish("cant_check", "repo_not_readable", `GitHub repository ${claim.owner}/${claim.repo}`, [], ["Whether the repository exists or is private"], []);
  if (rs === 301 || rs === 302 || rs === 307 || rs === 308) return finish("cant_check", "repo_moved", `GitHub repository ${claim.owner}/${claim.repo}`, [], [], [{ fact: "location", value: repoResult.response.headers.get("Location"), from: `${root}#Location` }]);
  if (rs === 451) return finish("cant_check", "repo_unavailable", `GitHub repository ${claim.owner}/${claim.repo}`, [], [], []);
  if (rs === 599 || rs >= 500 || (rs >= 200 && rs < 300 && !repoResult.data)) return finish("cant_check", "source_unavailable", `GitHub repository ${claim.owner}/${claim.repo}`, [], [], []);
  if (rs !== 200 || repoResult.data?.private !== false) return finish("cant_check", "repo_not_readable", `GitHub repository ${claim.owner}/${claim.repo}`, [], [], []);
  const get = (path: string) => read(path);
  const absence = (r: Response, missingReason = "source_unavailable") => r.status === 404 ? "contradicted" as const : r.status === 403 || r.status === 429 ? "cant_check" as const : "cant_check" as const;
  const failure = (r: Response, notFoundReason = "source_unavailable") => isRateLimited(r) ? ["cant_check" as Verdict, "github_rate_limited", retrySeconds(r)] as const : r.status === 599 || r.status >= 500 || r.status === 403 ? ["cant_check" as Verdict, "source_unavailable", null] as const : r.status === 404 ? ["contradicted" as Verdict, notFoundReason, null] as const : ["cant_check" as Verdict, "source_unavailable", null] as const;
  const simpleFact = (name: string, value: unknown, path: string): Fact => ({ fact: name, value, from: `${path}#${name}` });
  if (claim.kind === "pr_merged" || claim.kind === "pr_state") {
    const path = `${root}/pulls/${claim.number}`, x = await get(path), d = x.data;
    if (x.response.status !== 200 || !d) { const [v, why, retry] = failure(x.response, "pull_not_found"); return finish(v, why, `GitHub pull request ${claim.owner}/${claim.repo}#${claim.number}`, [], [], [], [], retry); }
    const facts = claim.kind === "pr_merged" ? [simpleFact("merged", d.merged, path), simpleFact("merged_at", d.merged_at, path), simpleFact("merge_commit_sha", d.merge_commit_sha, path), simpleFact("base.ref", d.base?.ref, path)] : [simpleFact("state", d.state, path), simpleFact("merged", d.merged, path)];
    const observed = claim.kind === "pr_merged" ? d.merged === true ? "merged" : d.merged === false ? "not_merged" : "unknown" : d.merged === true ? "merged" : d.state === "open" ? "open" : d.state === "closed" ? "closed_unmerged" : "unknown";
    if (observed === "unknown") return finish("cant_check", "source_unavailable", `GitHub pull request ${claim.owner}/${claim.repo}#${claim.number}`, [], [], facts);
    const verdict: Verdict = claim.kind === "pr_merged" ? observed === "merged" ? "confirmed" : "contradicted" : observed === claim.expected_state ? "confirmed" : "contradicted";
    return finish(verdict, verdict === "contradicted" ? "claim_contradicted" : null, `GitHub pull request ${claim.owner}/${claim.repo}#${claim.number}, field ${claim.kind === "pr_merged" ? "merged" : "state"}`, [claim.kind === "pr_merged" ? `At ${checkedAt}, GitHub reported PR #${claim.number} ${d.merged ? "as merged" : "as not merged"}.` : `GitHub reported PR #${claim.number} as ${observed}.`], ["That CI passed", "That the change is deployed"], facts);
  }
  if (claim.kind === "issue_closed") {
    const path = `${root}/issues/${claim.number}`, x = await get(path), d = x.data;
    if (x.response.status === 301) return finish("cant_check", "issue_moved", `GitHub issue ${claim.owner}/${claim.repo}#${claim.number}`, [], [], [simpleFact("location", x.response.headers.get("Location"), path)]);
    if (x.response.status === 410) return finish("cant_check", "issue_deleted", `GitHub issue ${claim.owner}/${claim.repo}#${claim.number}`, [], [], []);
    if (x.response.status !== 200 || !d) { const [v, why, retry] = failure(x.response, "issue_not_found"); return finish(v, why, `GitHub issue ${claim.owner}/${claim.repo}#${claim.number}`, [], [], [], [], retry); }
    if (Object.prototype.hasOwnProperty.call(d, "pull_request")) return finish("cant_check", "wrong_kind", `GitHub issue ${claim.owner}/${claim.repo}#${claim.number}`, [], [], [simpleFact("pull_request", true, path)]);
    const facts = [simpleFact("state", d.state, path), simpleFact("state_reason", d.state_reason, path), simpleFact("closed_at", d.closed_at, path)];
    const verdict: Verdict = d.state === "closed" ? "confirmed" : d.state === "open" ? "contradicted" : "cant_check";
    return finish(verdict, verdict === "cant_check" ? "unknown_issue_state" : verdict === "contradicted" ? "claim_contradicted" : null, `GitHub issue ${claim.owner}/${claim.repo}#${claim.number}, field state`, [`GitHub reported issue #${claim.number} as ${d.state}.`], ["Whether a closed issue was resolved as completed"], facts);
  }
  if (claim.kind === "tag_exists") {
    const path = `${root}/git/ref/tags/${encodeURIComponent(claim.tag)}`, x = await get(path), d = x.data;
    if (x.response.status !== 200 || !d) { const [v, why, retry] = failure(x.response, "tag_not_found"); return finish(v, why, `GitHub tag ${claim.owner}/${claim.repo}:${claim.tag}`, [], [], [], [], retry); }
    let objectSha = d.object?.sha, targetSha = objectSha;
    if (typeof objectSha !== "string" || !shaPattern.test(objectSha) || typeof d.object?.type !== "string") return finish("cant_check", "source_unavailable", `GitHub tag ${claim.owner}/${claim.repo}:${claim.tag}`, [], [], [simpleFact("object.sha", objectSha, path), simpleFact("object.type", d.object?.type, path)]);
    const facts = [simpleFact("object.sha", objectSha, path), simpleFact("object.type", d.object?.type, path)];
    if (d.object?.type === "tag") {
      const peelPath = `${root}/git/tags/${encodeURIComponent(objectSha)}`, peeled = await get(peelPath);
      if (peeled.response.status !== 200 || !peeled.data) { const [v, why, retry] = failure(peeled.response); return finish(v, why, `GitHub tag ${claim.owner}/${claim.repo}:${claim.tag}`, [], [], facts, [], retry); }
      targetSha = peeled.data.object?.sha; facts.push(simpleFact("object.sha", peeled.data.object?.sha, peelPath), simpleFact("object.type", peeled.data.object?.type, peelPath));
      if (typeof targetSha !== "string" || !shaPattern.test(targetSha)) return finish("cant_check", "source_unavailable", `GitHub tag ${claim.owner}/${claim.repo}:${claim.tag}`, [], [], facts);
    }
    const verdict: Verdict = claim.sha === undefined || targetSha === claim.sha ? "confirmed" : "contradicted";
    return finish(verdict, verdict === "contradicted" ? "tag_target_mismatch" : null, `GitHub tag ${claim.owner}/${claim.repo}:${claim.tag}`, [`GitHub ${verdict === "confirmed" ? "has" : "has a different target for"} tag ${claim.tag}.`], ["That the tagged code is safe or deployed"], facts, claim.sha ? [{ statement: `Tag target ${targetSha} ${verdict === "confirmed" ? "matches" : "does not match"} requested SHA.`, rule: "Peel annotated tag objects, then compare object SHA." }] : []);
  }
  if (claim.kind === "release_published") {
    const path = `${root}/releases/tags/${encodeURIComponent(claim.tag)}`, x = await get(path), d = x.data;
    if (x.response.status !== 200 || !d) { const [v, why, retry] = failure(x.response, "release_not_found"); return finish(v, why, `GitHub release ${claim.owner}/${claim.repo}:${claim.tag}`, [], [], [], [], retry); }
    const verdict: Verdict = d.draft === false ? "confirmed" : d.draft === true ? "contradicted" : "cant_check";
    const facts = [simpleFact("draft", d.draft, path), simpleFact("prerelease", d.prerelease, path), simpleFact("published_at", d.published_at, path)];
    return finish(verdict, verdict === "confirmed" ? null : verdict === "contradicted" ? "release_not_published" : "source_unavailable", `GitHub release ${claim.owner}/${claim.repo}:${claim.tag}, fields draft and published_at`, [`GitHub reported release ${claim.tag} as ${d.draft ? "a draft" : "published"}.`], ["That the release is installed or deployed"], facts);
  }
  if (claim.kind === "commit_on_branch") {
    const branch = encodeURIComponent(claim.branch), branchPath = `${root}/branches/${branch}`, b = await get(branchPath);
    if (b.response.status !== 200 || !b.data) { const [v, why, retry] = failure(b.response, "branch_not_found"); return finish(v, why, `GitHub branch ${claim.owner}/${claim.repo}:${claim.branch}`, [], [], [], [], retry); }
    const comparePath = `${root}/compare/${branch}...${claim.sha}`, x = await get(comparePath), d = x.data;
    if (x.response.status !== 200 || !d) { const [v, why, retry] = failure(x.response, "commit_not_found"); return finish(v, why, `GitHub compare ${claim.branch}...${claim.sha}`, [], [], [simpleFact("sha", claim.sha, comparePath)], [], retry); }
    const verdict: Verdict = ["identical", "behind"].includes(d.status) ? "confirmed" : ["ahead", "diverged"].includes(d.status) ? "contradicted" : "cant_check";
    return finish(verdict, verdict === "cant_check" ? "unknown_compare_status" : verdict === "contradicted" ? "commit_not_on_branch" : null, `GitHub branch ${claim.owner}/${claim.repo}:${claim.branch}, compare status`, [`Compare status was ${d.status}.`], ["Whether the commit's changes are deployed"], [simpleFact("status", d.status, comparePath), simpleFact("ahead_by", d.ahead_by, comparePath), simpleFact("behind_by", d.behind_by, comparePath), simpleFact("sha", claim.sha, comparePath)], [{ statement: `Requested SHA is ${verdict === "confirmed" ? "reachable from" : "not an ancestor of"} branch ${claim.branch}.`, rule: "GitHub compare status identical or behind means base SHA is reachable from head." }]);
  }
  // CI is handled below; it needs bounded, de-duplicated check-run pagination and the combined status endpoint.
  const checksPath = `${root}/commits/${claim.sha}/check-runs?per_page=100`;
  const runs: any[] = [];
  let next: string | undefined = checksPath;
  let count = 0;
  while (next && count < 3) {
    const page = await get(next); count++;
    if (page.response.status !== 200 || !page.data) { const [v, why, retry] = failure(page.response); return finish(v, why, `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], [], [], retry); }
    for (const run of page.data.check_runs ?? []) runs.push(run);
    const link = page.response.headers.get("Link") ?? "";
    const match = link.split(",").find(part => part.includes('rel="next"'))?.match(/<([^>]+)>/);
    next = match?.[1];
    if (next) {
      try { const u = new URL(next); if (u.origin !== "https://api.github.com" || u.pathname !== `${root}/commits/${claim.sha}/check-runs`) return finish("cant_check", "source_unavailable", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], []); next = `${u.pathname}${u.search}`; } catch { return finish("cant_check", "source_unavailable", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], []); }
    }
  }
  if (next || runs.length > 300) return finish("cant_check", "too_many_checks", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], []);
  const statusPath = `${root}/commits/${claim.sha}/status`, st = await get(statusPath);
  if (st.response.status !== 200 || !st.data) { const [v, why, retry] = failure(st.response); return finish(v, why, `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], [], [], retry); }
  const latest = new Map<string, any>();
  for (const run of runs) { const name = typeof run.name === "string" ? run.name : ""; const old = latest.get(name); if (!old || Date.parse(run.completed_at ?? run.started_at ?? run.created_at) >= Date.parse(old.completed_at ?? old.started_at ?? old.created_at)) latest.set(name, run); }
  let inScope = [...latest.entries()];
  if (claim.check_names !== undefined) inScope = inScope.filter(([name]) => claim.check_names.includes(name));
  const statuses: any[] = Array.isArray(st.data.statuses) ? st.data.statuses : [];
  const allRuns = [...latest.values()];
  const selectedRuns = claim.check_names === undefined ? allRuns : allRuns.filter(run => claim.check_names.includes(run.name));
  const missingNames = (claim.check_names ?? []).filter((name: string) => !latest.has(name));
  const facts: Fact[] = [];
  let unknown: string | undefined, pending = false, bad = false, ambiguous = false, green = true;
  const greenConclusions = ["success", "neutral", "skipped"], failedConclusions = ["failure", "timed_out", "startup_failure"], ambiguousConclusions = ["cancelled", "action_required", "stale"], pendingStatuses = ["queued", "in_progress", "waiting", "requested", "pending"];
  for (const run of selectedRuns) {
    facts.push(simpleFact(`${run.name}.status`, run.status, checksPath), simpleFact(`${run.name}.conclusion`, run.conclusion, checksPath));
    if (run.status !== "completed") { if (pendingStatuses.includes(run.status)) { pending = true; green = false; } else unknown = "unknown_check_status"; }
    else if (greenConclusions.includes(run.conclusion)) { /* green */ }
    else if (failedConclusions.includes(run.conclusion)) { bad = true; green = false; }
    else if (ambiguousConclusions.includes(run.conclusion)) { ambiguous = true; green = false; }
    else unknown = "unknown_check_conclusion";
  }
  for (const item of statuses) {
    if (claim.check_names !== undefined && !claim.check_names.includes(item.context)) continue;
    facts.push(simpleFact(`${item.context}.state`, item.state, statusPath));
    if (item.state === "success") { /* green */ }
    else if (["failure", "error"].includes(item.state)) { bad = true; green = false; }
    else if (item.state === "pending") { pending = true; green = false; }
    else unknown = "unknown_status_state";
  }
  if (unknown) return finish("cant_check", unknown, `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], facts);
  if (missingNames.length) return finish("cant_check", "check_not_found", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], facts);
  const countInScope = selectedRuns.length + statuses.filter((item: any) => claim.check_names === undefined || claim.check_names.includes(item.context)).length;
  if (!countInScope) return finish("cant_check", "no_ci_found", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], facts);
  if (claim.expected_conclusion === "success") {
    const verdict: Verdict = bad || ambiguous || pending ? "contradicted" : "confirmed";
    const reason = bad ? "ci_failed" : ambiguous ? "ci_not_green" : pending ? "ci_not_concluded" : null;
    return finish(verdict, reason, `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [`All ${countInScope} in-scope check items were ${verdict === "confirmed" ? "green" : "not green"}.`], ["That CI will remain green"], facts);
  }
  if (bad) return finish("confirmed", null, `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, ["At least one in-scope check item failed."], ["That the failure is a product defect"], facts);
  if (ambiguous) return finish("cant_check", "ci_ambiguous_conclusion", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, [], [], facts);
  if (pending) return finish("contradicted", "ci_not_concluded", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, ["No in-scope check item had failed at read time."], ["That checks will pass or fail later"], facts);
  return finish("contradicted", "ci_all_green", `GitHub CI for ${claim.owner}/${claim.repo}@${claim.sha}`, ["All in-scope check items were green."], ["That CI will remain green"], facts);
}

export async function checkClaims(env: Env, claims: unknown[], observe?: (response: Response) => void): Promise<ClaimResult[]> {
  const repoCache = new Map<string, Promise<{ response: Response; data?: any }>>();
  const repoRead = (repoPath: string) => {
    let cached = repoCache.get(repoPath);
    if (!cached) {
      cached = (async () => {
        try {
          const response = await githubFetch(env, repoPath);
          observe?.(response);
          let data: any; if (response.status >= 200 && response.status < 300) { try { data = await response.json(); } catch { /* handled upstream */ } }
          return { response, data };
        } catch { return { response: new Response(null, { status: 599 }) }; }
      })(); repoCache.set(repoPath, cached);
    }
    return cached;
  };
  const out: ClaimResult[] = [];
  let limited: number | undefined;
  for (let i = 0; i < claims.length; i++) {
    if (limited !== undefined) { out.push(shell(i, claims[i], "github_rate_limited", new Date().toISOString(), [], limited)); continue; }
    const checked = await checkClaim(env, i, claims[i], repoRead, undefined, observe);
    out.push(checked.result);
    if (checked.rateLimited !== undefined) limited = checked.rateLimited;
  }
  return out;
}

/** Return fail-closed results when no GitHub credential is configured, without making source calls. */
export function sourceUnavailableClaims(claims: unknown[]): ClaimResult[] {
  return claims.map((claim, index) => {
    const checkedAt = new Date().toISOString();
    return shell(index, claim, invalidReason(claim) ?? "source_unavailable", checkedAt);
  });
}
