package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jitokim/raft-claim-check/cli/internal/raft"
	"github.com/jitokim/raft-claim-check/cli/internal/spool"
)

type outcome int

const (
	outStored   outcome = iota // the app stored it; removed from the spool
	outKept                    // still pending in the spool
	outRejected                // moved to spool/rejected/
)

// submitResult is the outcome of one submit_receipt call, following the
// design's submit-failure table.
type submitResult struct {
	outcome   outcome
	duplicate bool
	stop      bool   // flush stops here (401, 429, other 4xx without an app code, Raft CLI missing, not logged in)
	summary   string // one line, without the receipt ID
}

// appError is the app's {error, hint} body.
type appError struct {
	Error string `json:"error"`
	Hint  string `json:"hint"`
}

// knownSubmitErrors are submit_receipt's own error codes (design-v2.md,
// "## Actions"). Only these prove that the app refused the receipt; a 4xx
// without one may come from Raft itself (scope, install), not the app.
var knownSubmitErrors = map[string]bool{
	"invalid_request":    true,
	"schema_unsupported": true,
	"binding_mismatch":   true,
	"key_not_registered": true,
	"key_revoked":        true,
	"bad_signature":      true,
	"schema_invalid":     true,
	"clock_skew":         true,
	"receipt_too_old":    true,
	"receipt_too_large":  true,
}

// parseAppError reads the app's {error, hint} body. ok is false when the
// body is not JSON, "error" is not a string, or it is empty.
func parseAppError(result []byte) (e appError, ok bool) {
	if json.Unmarshal(result, &e) != nil || e.Error == "" {
		return appError{}, false
	}
	e.Hint = oneLine(e.Hint)
	return e, true
}

// statusLine is "<status> <code>", or just the status when the body has no
// app error code.
func statusLine(status int, result []byte) string {
	if ae, ok := parseAppError(result); ok {
		return fmt.Sprintf("%d %s", status, ae.Error)
	}
	return fmt.Sprint(status)
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// submit sends a pending entry and applies the outcome to the spool: the
// file is removed only after a 200 or 201 whose receipt_id equals the local
// ID, moved to rejected/ on 400, 403, 409 or 413 with a known
// submit_receipt error code, and kept otherwise. A kept 4xx stops flush.
func (a *app) submit(p *profile, e spool.Entry) submitResult {
	loginHint := fmt.Sprintf("run 'raft integration login --service %s', then 'claim-check flush'", p.service)
	status, result, err := p.raft.Invoke("submit_receipt", e.Body)
	if err != nil {
		switch {
		case errors.Is(err, raft.ErrNotInstalled):
			return submitResult{outcome: outKept, stop: true,
				summary: fmt.Sprintf("kept in spool: %v; hint: this machine needs a Raft CLI with Agent Login", err)}
		case errors.Is(err, raft.ErrNotLoggedIn):
			return submitResult{outcome: outKept, stop: true,
				summary: fmt.Sprintf("kept in spool: not logged in; hint: %s", loginHint)}
		case errors.Is(err, raft.ErrTimeout):
			return submitResult{outcome: outKept,
				summary: fmt.Sprintf("kept in spool: %v; 'claim-check flush' retries it", err)}
		}
		return submitResult{outcome: outKept,
			summary: fmt.Sprintf("kept in spool: submit outcome unknown: %v; 'claim-check flush' retries it", err)}
	}
	switch {
	case status == 200 || status == 201:
		var body struct {
			ReceiptID string `json:"receipt_id"`
			Duplicate bool   `json:"duplicate"`
		}
		if json.Unmarshal(result, &body) != nil || body.ReceiptID != e.ID {
			return submitResult{outcome: outKept,
				summary: fmt.Sprintf("kept in spool: the app answered %d without the matching receipt_id (got %q)", status, body.ReceiptID)}
		}
		if err := spool.Remove(e); err != nil {
			a.logf("warning: stored, but could not remove %s: %v", e.Path, err)
		}
		r := submitResult{outcome: outStored, duplicate: body.Duplicate, summary: "stored"}
		if body.Duplicate {
			r.summary = "stored (duplicate)"
		}
		return r
	case status == 401:
		return submitResult{outcome: outKept, stop: true,
			summary: fmt.Sprintf("kept in spool: %s; hint: %s", statusLine(status, result), loginHint)}
	case status == 429:
		return submitResult{outcome: outKept, stop: true,
			summary: "kept in spool: 429 rate_limited; 'claim-check flush' retries it later"}
	case status >= 500:
		return submitResult{outcome: outKept,
			summary: fmt.Sprintf("kept in spool: %s; 'claim-check flush' retries it", statusLine(status, result))}
	case status == 400 || status == 403 || status == 409 || status == 413:
		ae, ok := parseAppError(result)
		if !ok || !knownSubmitErrors[ae.Error] {
			// No app code: Raft refused before the app (scope, install), so
			// every later receipt would fail the same way.
			return submitResult{outcome: outKept, stop: true,
				summary: fmt.Sprintf("kept in spool: %s without a known submit_receipt error, outcome unknown; 'claim-check flush' retries it", statusLine(status, result))}
		}
		rej := spool.Rejection{Status: status, Error: ae.Error, Hint: ae.Hint}
		if err := spool.Reject(p.paths, e, rej, a.Now()); err != nil {
			return submitResult{outcome: outKept,
				summary: fmt.Sprintf("refused by the app (%d %s), but moving it to rejected/ failed: %v", status, ae.Error, err)}
		}
		msg := fmt.Sprintf("rejected: %d %s", status, ae.Error)
		if ae.Hint != "" {
			msg += ": " + ae.Hint
		}
		return submitResult{outcome: outRejected, summary: msg + "; moved to spool/rejected/, not retried"}
	}
	return submitResult{outcome: outKept, stop: status >= 400 && status < 500,
		summary: fmt.Sprintf("kept in spool: unexpected status %d, outcome unknown; 'claim-check flush' retries it", status)}
}
