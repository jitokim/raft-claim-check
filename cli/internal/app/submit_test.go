package app

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/raft"
)

func status(code int, body string) handler {
	return func([]byte) (int, []byte, error) { return code, []byte(body), nil }
}

func failWith(err error) handler {
	return func([]byte) (int, []byte, error) { return 0, nil, err }
}

// TestSubmitFailureTable covers every row of the design's submit-failure
// table, plus the two success responses and the outcome-unknown cases.
func TestSubmitFailureTable(t *testing.T) {
	cases := []struct {
		name    string
		h       handler
		want    outcome
		message string
	}{
		{"201 matching receipt_id", acceptSubmit(201), outStored, "stored"},
		{"200 duplicate matching receipt_id", acceptSubmit(200), outStored, "stored (duplicate)"},
		{"201 with another receipt_id", status(201, `{"receipt_id":"rcpt_other","duplicate":false}`), outKept, "without the matching receipt_id"},
		{"201 without receipt_id", status(201, `{}`), outKept, "without the matching receipt_id"},
		{"raft not on PATH / no integration", failWith(fmt.Errorf("%w: x", raft.ErrNotInstalled)), outKept, "Raft CLI with Agent Login"},
		{"not logged in", failWith(fmt.Errorf("%w", raft.ErrNotLoggedIn)), outKept, "raft integration login --service claim-check', then 'claim-check flush'"},
		{"401 not_authenticated", status(401, `{"error":"not_authenticated","hint":"log in"}`), outKept, "raft integration login --service claim-check"},
		{"offline / unknown outcome", failWith(fmt.Errorf("%w: offline", raft.ErrUnknownOutcome)), outKept, "outcome unknown"},
		{"timeout", failWith(fmt.Errorf("%w after 30s", raft.ErrTimeout)), outKept, "flush' retries"},
		{"429", status(429, `{"error":"rate_limited","hint":"slow down"}`), outKept, "429"},
		{"500", status(500, `{"error":"internal_error","hint":"x"}`), outKept, "500"},
		{"503 non-JSON", status(503, `"upstream"`), outKept, "503"},
		{"400", status(400, `{"error":"schema_invalid","hint":"run.argv is too long"}`), outRejected, "400 schema_invalid"},
		{"403", status(403, `{"error":"key_revoked","hint":"the key is revoked"}`), outRejected, "403 key_revoked"},
		{"409 unknown code", status(409, `{"error":"conflict","hint":"x"}`), outKept, "409 conflict without a known submit_receipt error, outcome unknown"},
		{"400 without a body", status(400, ``), outKept, "kept in spool: 400 without a known submit_receipt error, outcome unknown; 'claim-check flush' retries it"},
		{"413", status(413, `{"error":"receipt_too_large","hint":"x"}`), outRejected, "413 receipt_too_large"},
		{"unexpected 404", status(404, `{"error":"nope"}`), outKept, "unexpected status 404"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			p := h.paths()
			h.handlers["submit_receipt"] = c.h
			if code := h.run("run", "--", "true"); code != 0 {
				t.Fatalf("exit %d: the child's code must pass through", code)
			}
			if !strings.Contains(h.stderr.String(), c.message) {
				t.Fatalf("line %q does not contain %q", h.stderr.String(), c.message)
			}
			pending, rejected := h.spoolFiles(p.SpoolDir), h.spoolFiles(p.RejectedDir)
			switch c.want {
			case outStored:
				if len(pending)+len(rejected) != 0 {
					t.Fatalf("pending %d rejected %d, want none", len(pending), len(rejected))
				}
			case outKept:
				if len(pending) != 1 || len(rejected) != 0 {
					t.Fatalf("pending %d rejected %d, want 1/0", len(pending), len(rejected))
				}
			case outRejected:
				if len(pending) != 0 || len(rejected) != 1 {
					t.Fatalf("pending %d rejected %d, want 0/1", len(pending), len(rejected))
				}
				data, _ := os.ReadFile(rejected[0])
				if !strings.Contains(string(data), `"rejection":{"error":`) || !strings.Contains(string(data), `"receipt":{"payload"`) {
					t.Fatalf("rejected file = %s", data)
				}
			}
		})
	}
}

// invokeOutput answers with raft's raw --json output, read the way
// raft.CLI.Invoke reads it: unparsed output is an unknown outcome.
func invokeOutput(stdout string) handler {
	return func([]byte) (int, []byte, error) {
		if code, result, ok := raft.ParseInvokeOutput([]byte(stdout)); ok {
			return code, result, nil
		}
		return 0, nil, fmt.Errorf("%w (%s)", raft.ErrUnknownOutcome, stdout)
	}
}

// invokeFailed is raft's real failure output (captured 2026-10-06).
func invokeFailed(code, message string) string {
	return string(jsonBytes(map[string]any{"ok": false, "error": map[string]any{
		"code": code, "message": message, "fault_domain": nil, "layer": nil,
		"retryable": nil, "effect": nil, "correlation_id": nil}}))
}

// TestSubmitInvokeFailedOutput applies the submit-failure table to the
// status and body embedded in an INTEGRATION_INVOKE_FAILED message.
func TestSubmitInvokeFailedOutput(t *testing.T) {
	failed := func(status int, body string) string {
		return invokeFailed(raft.InvokeFailedCode, fmt.Sprintf("service action failed (HTTP %d); response body: %s", status, body))
	}
	cases := []struct {
		name      string
		stdout    string
		want      outcome
		message   string
		rejection map[string]any
	}{
		{"404 receipt_not_found", failed(404, `{"error":"receipt_not_found","hint":"no such receipt"}`), outKept, "unexpected status 404, outcome unknown", nil},
		{"403 key_revoked", failed(403, `{"error":"key_revoked","hint":"the key is revoked; run key register"}`), outRejected,
			"rejected: 403 key_revoked: the key is revoked; run key register",
			map[string]any{"status": float64(403), "error": "key_revoked", "hint": "the key is revoked; run key register"}},
		{"401", failed(401, `{"error":"not_authenticated","hint":"log in"}`), outKept,
			"kept in spool: 401 not_authenticated; hint: run 'raft integration login --service claim-check'", nil},
		{"429", failed(429, `{"error":"rate_limited","hint":"slow down"}`), outKept, "kept in spool: 429 rate_limited", nil},
		{"500", failed(500, `{"error":"internal_error","hint":"x"}`), outKept, "kept in spool: 500 internal_error", nil},
		{"no HTTP status", invokeFailed(raft.InvokeFailedCode, "service action failed: connection reset"), outKept, "outcome unknown", nil},
		{"non-JSON body is kept", failed(403, `<html>Forbidden</html>`), outKept,
			"kept in spool: 403 without a known submit_receipt error, outcome unknown; 'claim-check flush' retries it", nil},
		{"Raft-side 403 with an error object", failed(403, `{"error":{"code":"INTEGRATION_INVOKE_FAILED","message":"missing scope"}}`), outKept,
			"kept in spool: 403 without a known submit_receipt error, outcome unknown", nil},
		{"Raft-side 403 with a string code", failed(403, `{"error":"INTEGRATION_INVOKE_FAILED","hint":"missing scope"}`), outKept,
			"kept in spool: 403 INTEGRATION_INVOKE_FAILED without a known submit_receipt error, outcome unknown", nil},
		{"400 unknown app code", failed(400, `{"error":"something_new","hint":"h"}`), outKept, "outcome unknown", nil},
		{"400 schema_invalid", failed(400, `{"error":"schema_invalid","hint":"run.argv is too long"}`), outRejected,
			"rejected: 400 schema_invalid: run.argv is too long",
			map[string]any{"status": float64(400), "error": "schema_invalid", "hint": "run.argv is too long"}},
		{"other error code with HTTP 403", invokeFailed("INTEGRATION_NOT_FOUND", `service action failed (HTTP 403); response body: {"error":"key_revoked","hint":"h"}`),
			outKept, "submit outcome unknown", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			p := h.paths()
			h.handlers["submit_receipt"] = invokeOutput(c.stdout)
			if code := h.run("run", "--", "true"); code != 0 {
				t.Fatalf("exit %d: the child's code must pass through", code)
			}
			if !strings.Contains(h.stderr.String(), c.message) {
				t.Fatalf("line %q does not contain %q", h.stderr.String(), c.message)
			}
			pending, rejected := h.spoolFiles(p.SpoolDir), h.spoolFiles(p.RejectedDir)
			switch c.want {
			case outKept:
				if len(pending) != 1 || len(rejected) != 0 {
					t.Fatalf("pending %d rejected %d, want 1/0", len(pending), len(rejected))
				}
			case outRejected:
				if len(pending) != 0 || len(rejected) != 1 {
					t.Fatalf("pending %d rejected %d, want 0/1", len(pending), len(rejected))
				}
				data, _ := os.ReadFile(rejected[0])
				var file struct {
					Rejection map[string]any `json:"rejection"`
				}
				if err := json.Unmarshal(data, &file); err != nil {
					t.Fatalf("rejected file = %s: %v", data, err)
				}
				for k, v := range c.rejection {
					if file.Rejection[k] != v {
						t.Fatalf("rejection.%s = %v, want %v (file %s)", k, file.Rejection[k], v, data)
					}
				}
			}
		})
	}
}

// spoolThree leaves three receipts in the spool, signed one hour apart, and
// returns their IDs oldest first.
func spoolThree(t *testing.T, h *harness) []string {
	t.Helper()
	h.handlers["submit_receipt"] = status(503, `{}`)
	start := h.now
	var ids []string
	// Spool them newest first so file order is not signed order.
	for i := 2; i >= 0; i-- {
		h.now = start.Add(time.Duration(i) * time.Hour)
		h.mustRun("run", "--", "true")
		bodies := h.submitted()
		_, id := payloadOf(t, bodies[len(bodies)-1])
		ids = append([]string{id}, ids...)
	}
	h.now = start.Add(3 * time.Hour)
	h.calls = nil
	return ids
}

func (h *harness) submittedIDs() []string {
	var ids []string
	for _, b := range h.submitted() {
		_, id := payloadOf(h.t, b)
		ids = append(ids, id)
	}
	return ids
}

func TestFlushOldestFirst(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	ids := spoolThree(t, h)
	h.handlers["submit_receipt"] = acceptSubmit(201)
	h.mustRun("flush")
	if got := h.submittedIDs(); strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("order %v, want %v", got, ids)
	}
	if n := len(h.spoolFiles(h.paths().SpoolDir)); n != 0 {
		t.Fatalf("%d still pending", n)
	}
}

func TestFlushStopsOn401And429(t *testing.T) {
	for _, code := range []int{401, 429} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			ids := spoolThree(t, h)
			n := 0
			h.handlers["submit_receipt"] = func(body []byte) (int, []byte, error) {
				n++
				if n == 2 {
					return code, []byte(`{"error":"x","hint":"y"}`), nil
				}
				return acceptSubmit(201)(body)
			}
			if exit := h.run("flush"); exit != 75 {
				t.Fatalf("exit %d, want 75", exit)
			}
			if got := h.submittedIDs(); strings.Join(got, ",") != strings.Join(ids[:2], ",") {
				t.Fatalf("submitted %v, want the two oldest and then stop", got)
			}
			if pending := h.spoolFiles(h.paths().SpoolDir); len(pending) != 2 {
				t.Fatalf("%d pending, want 2", len(pending))
			}
			if !strings.Contains(h.stderr.String(), "1 stored, 0 rejected, 0 expired, 2 still pending") {
				t.Fatalf("summary: %s", h.stderr.String())
			}
		})
	}
}

// A 4xx without a known app error code comes from Raft (scope, install), not
// the receipt, so flush stops instead of retrying every receipt against it.
// A 5xx keeps going.
func TestFlushStopsOnUnknown4xx(t *testing.T) {
	cases := []struct {
		name  string
		code  int
		body  string
		stops bool
	}{
		{"Raft-side 403", 403, `{"error":{"code":"INTEGRATION_INVOKE_FAILED","message":"missing scope"}}`, true},
		{"400 without a body", 400, ``, true},
		{"404", 404, `{"error":"nope"}`, true},
		{"500", 500, `{"error":"internal_error","hint":"x"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			ids := spoolThree(t, h)
			n := 0
			h.handlers["submit_receipt"] = func(body []byte) (int, []byte, error) {
				n++
				if n == 2 {
					return c.code, []byte(c.body), nil
				}
				return acceptSubmit(201)(body)
			}
			if exit := h.run("flush"); exit != 75 {
				t.Fatalf("exit %d, want 75", exit)
			}
			want, summary := ids[:2], "1 stored, 0 rejected, 0 expired, 2 still pending"
			if !c.stops {
				want, summary = ids, "2 stored, 0 rejected, 0 expired, 1 still pending"
			}
			if got := h.submittedIDs(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("submitted %v, want %v", got, want)
			}
			if !strings.Contains(h.stderr.String(), summary) {
				t.Fatalf("summary: %s", h.stderr.String())
			}
		})
	}
}

// A 4xx without a known app error code is kept and counted as pending, and a
// later flush retries and stores it.
func TestFlushRetriesReceiptKeptOnUnknown4xx(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	p := h.paths()
	h.handlers["submit_receipt"] = invokeOutput(invokeFailed(raft.InvokeFailedCode,
		`service action failed (HTTP 403); response body: {"error":{"code":"INTEGRATION_INVOKE_FAILED","message":"missing scope"}}`))
	h.mustRun("run", "--", "true")
	_, id := payloadOf(t, h.submitted()[0])
	if code := h.run("flush"); code != 75 {
		t.Fatalf("flush exit %d, want 75", code)
	}
	if !strings.Contains(h.stderr.String(), "0 stored, 0 rejected, 0 expired, 1 still pending") {
		t.Fatalf("summary: %s", h.stderr.String())
	}
	if len(h.spoolFiles(p.SpoolDir)) != 1 || len(h.spoolFiles(p.RejectedDir)) != 0 {
		t.Fatal("receipt not kept pending")
	}
	h.calls = nil
	h.handlers["submit_receipt"] = acceptSubmit(201)
	h.mustRun("flush")
	if got := h.submittedIDs(); len(got) != 1 || got[0] != id {
		t.Fatalf("submitted %v, want %s", got, id)
	}
	if len(h.spoolFiles(p.SpoolDir))+len(h.spoolFiles(p.RejectedDir)) != 0 {
		t.Fatal("receipt not stored on the later flush")
	}
}

func TestFlushMovesReceiptsOlderThan7DaysToRejected(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	p := h.paths()
	h.handlers["submit_receipt"] = status(503, `{}`)
	t0 := h.now
	h.mustRun("run", "--", "true") // signed at t0
	h.now = t0.Add(2 * 24 * time.Hour)
	h.mustRun("run", "--", "true") // signed at t0+2d
	_, young := payloadOf(t, h.submitted()[1])
	h.calls = nil

	h.now = t0.Add(7*24*time.Hour + time.Minute) // first is 7d+1m old, second 5d
	h.handlers["submit_receipt"] = acceptSubmit(201)
	h.mustRun("flush")
	if got := h.submittedIDs(); len(got) != 1 || got[0] != young {
		t.Fatalf("submitted %v, want only the young receipt", got)
	}
	rejected := h.spoolFiles(p.RejectedDir)
	if len(rejected) != 1 {
		t.Fatalf("%d rejected, want 1", len(rejected))
	}
	data, _ := os.ReadFile(rejected[0])
	if !strings.Contains(string(data), `"error":"receipt_too_old"`) {
		t.Fatalf("rejected file: %s", data)
	}
	// Rejected files are deleted after 30 days.
	h.now = h.now.Add(31 * 24 * time.Hour)
	h.mustRun("flush")
	if n := len(h.spoolFiles(p.RejectedDir)); n != 0 {
		t.Fatalf("%d rejected files after 30 days", n)
	}
}

func TestFlushQuarantinesUnreadableFiles(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	p := h.paths()
	if err := p.EnsureStateDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SpoolFile("rcpt_broken"), []byte(`{"receipt":`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun("flush")
	if len(h.spoolFiles(p.SpoolDir)) != 0 || len(h.spoolFiles(p.RejectedDir)) != 1 {
		t.Fatal("unreadable file not moved to rejected/")
	}
}
