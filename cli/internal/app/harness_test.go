package app

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/raft"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

type call struct {
	service, action string
	body            []byte
}

type handler func(body []byte) (int, []byte, error)

// fakeRaft is the test double of raft.Raft. No test runs the real raft.
type fakeRaft struct {
	h         *harness
	service   string
	whoamiErr error
}

func (f *fakeRaft) Whoami() (string, string, error) {
	if f.whoamiErr != nil {
		return "", "", f.whoamiErr
	}
	return f.h.server, f.h.agent, nil
}

func (f *fakeRaft) Invoke(action string, body []byte) (int, []byte, error) {
	f.h.calls = append(f.h.calls, call{f.service, action, append([]byte(nil), body...)})
	if hd, ok := f.h.handlers[action]; ok {
		return hd(body)
	}
	return 0, nil, fmt.Errorf("%w: no handler for %s", raft.ErrUnknownOutcome, action)
}

type harness struct {
	t              *testing.T
	env            map[string]string
	environ        []string
	server, agent  string
	whoamiErr      error
	handlers       map[string]handler
	calls          []call
	services       []string // service ids passed to NewRaft
	stdout, stderr bytes.Buffer
	out            io.Writer // replaces stdout when set
	now            time.Time
	cwd            string
	home           string // returned by UserHomeDir, masked as "~"
	homeErr        error  // returned by UserHomeDir when set
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{
		t: t,
		env: map[string]string{
			"HOME":            filepath.Join(root, "home"),
			"XDG_CONFIG_HOME": filepath.Join(root, "config"),
			"XDG_STATE_HOME":  filepath.Join(root, "state"),
		},
		server: "srv_test",
		agent:  "agent_test",
		now:    time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		cwd:    filepath.Join(root, "work"),
	}
	h.home = h.env["HOME"]
	if err := os.MkdirAll(h.cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	h.handlers = map[string]handler{
		"get_session": func([]byte) (int, []byte, error) {
			return 200, jsonBytes(map[string]any{"principal": map[string]any{"id": h.agent, "type": "agent"},
				"server": map[string]any{"id": h.server, "slug": "s"}}), nil
		},
		"register_key": func(body []byte) (int, []byte, error) {
			env, _, err := receipt.FindEnvelope(body)
			if err != nil {
				return 400, []byte(`{"error":"invalid_request","hint":"bad"}`), nil
			}
			pub, err := receipt.VerifyRegistration(env)
			if err != nil {
				return 400, []byte(`{"error":"bad_signature","hint":"bad"}`), nil
			}
			return 201, jsonBytes(map[string]any{"key_id": receipt.KeyID(pub), "status": "active"}), nil
		},
		"submit_receipt": acceptSubmit(201),
		"revoke_key": func(body []byte) (int, []byte, error) {
			return 200, body, nil
		},
		"list_keys": func([]byte) (int, []byte, error) {
			return 200, []byte(`{"keys":[]}`), nil
		},
	}
	return h
}

// acceptSubmit answers like the app storing the receipt.
func acceptSubmit(status int) handler {
	return func(body []byte) (int, []byte, error) {
		env, _, err := receipt.FindEnvelope(body)
		if err != nil {
			return 400, []byte(`{"error":"invalid_request","hint":"bad"}`), nil
		}
		return status, jsonBytes(map[string]any{"receipt_id": env.ReceiptID(), "duplicate": status == 200}), nil
	}
}

func jsonBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (h *harness) deps() Deps {
	var stdout io.Writer = &h.stdout
	if h.out != nil {
		stdout = h.out
	}
	return Deps{
		Stdin:  nil,
		Stdout: stdout,
		Stderr: &h.stderr,
		LookupEnv: func(k string) (string, bool) {
			v, ok := h.env[k]
			return v, ok
		},
		Environ: func() []string { return h.environ },
		NewRaft: func(s string) raft.Raft {
			h.services = append(h.services, s)
			return &fakeRaft{h: h, service: s, whoamiErr: h.whoamiErr}
		},
		Now:   func() time.Time { return h.now },
		Rand:  rand.Reader,
		Getwd: func() (string, error) { return h.cwd, nil },
		UserHomeDir: func() (string, error) {
			if h.homeErr != nil {
				return "", h.homeErr
			}
			return h.home, nil
		},
		Version: "2.0.0-test",
	}
}

// run runs claim-check with args and returns the exit code.
func (h *harness) run(args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	return Main(args, h.deps())
}

func (h *harness) mustRun(args ...string) {
	h.t.Helper()
	if code := h.run(args...); code != 0 {
		h.t.Fatalf("claim-check %v = %d\nstdout: %s\nstderr: %s", args, code, h.stdout.String(), h.stderr.String())
	}
}

func (h *harness) paths() keystore.Paths {
	h.t.Helper()
	p, err := keystore.Resolve(h.deps().LookupEnv, h.server, h.agent)
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

// setupKey runs key init and key register.
func (h *harness) setupKey() *keystore.Key {
	h.t.Helper()
	h.mustRun("key", "init")
	h.mustRun("key", "register", "--label", "test-machine")
	key, err := keystore.Load(h.paths())
	if err != nil {
		h.t.Fatal(err)
	}
	h.calls = nil
	return key
}

// submitted returns the bodies of submit_receipt calls.
func (h *harness) submitted() [][]byte {
	var out [][]byte
	for _, c := range h.calls {
		if c.action == "submit_receipt" {
			out = append(out, c.body)
		}
	}
	return out
}

func payloadOf(t *testing.T, body []byte) (receipt.Payload, string) {
	t.Helper()
	env, _, err := receipt.FindEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	var p receipt.Payload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p, env.ReceiptID()
}

func (h *harness) spoolFiles(dir string) []string {
	h.t.Helper()
	names, _ := filepath.Glob(filepath.Join(dir, "rcpt_*.json"))
	return names
}
