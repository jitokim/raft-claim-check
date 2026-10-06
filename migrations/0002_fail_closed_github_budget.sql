-- Phase 2 must never infer capacity from the historical 5,000-read seed.
-- The next check_claims request obtains a real /rate_limit observation.
UPDATE github_budget
SET remaining_reads = 0, reset_at = 0, reserved_inflight = 0
WHERE id = 1 AND reset_at = 0;
