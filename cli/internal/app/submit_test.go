package app

import (
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
		{"409", status(409, `{"error":"conflict","hint":"x"}`), outRejected, "409 conflict"},
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
