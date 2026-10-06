package app

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/raft"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func TestKeyInitRegisterShow(t *testing.T) {
	h := newHarness(t)
	h.mustRun("key", "init")
	p := h.paths()
	for _, f := range []string{p.KeyFile, p.MetaFile} {
		info, err := os.Stat(f)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, info, err)
		}
	}
	if dir, _ := os.Stat(p.KeyDir); dir.Mode().Perm() != 0o700 {
		t.Fatalf("key dir mode %v", dir.Mode())
	}
	if code := h.run("key", "init"); code != 1 || !strings.Contains(h.stderr.String(), "already exists") {
		t.Fatalf("second key init: %d %s", code, h.stderr.String())
	}

	h.mustRun("key", "register", "--label", "laptop")
	if len(h.calls) != 2 || h.calls[0].action != "get_session" || h.calls[1].action != "register_key" {
		t.Fatalf("calls = %+v", h.calls)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(h.calls[1].body, &body); err != nil || len(body) != 1 || body["registration"] == nil {
		t.Fatalf("register_key body = %s", h.calls[1].body)
	}
	env, _, _ := receipt.FindEnvelope(h.calls[1].body)
	var stmt receipt.Registration
	_ = json.Unmarshal(env.Payload, &stmt)
	if stmt.Schema != receipt.SchemaRegistration || stmt.ServerID != h.server || stmt.PrincipalID != h.agent ||
		stmt.Label == nil || *stmt.Label != "laptop" || stmt.CLIVersion != "2.0.0-test" || stmt.IssuedAt != "2026-10-06T09:00:00.000Z" {
		t.Fatalf("statement = %+v", stmt)
	}
	meta, err := keystore.LoadMeta(p)
	if err != nil || meta.BoundTo == nil || meta.BoundTo.ServerID != h.server || meta.BoundTo.PrincipalID != h.agent {
		t.Fatalf("meta = %+v %v", meta, err)
	}

	h.mustRun("key", "show")
	out := h.stdout.String()
	if !strings.Contains(out, meta.KeyID) || !strings.Contains(out, meta.PublicKey) || !strings.Contains(out, "server "+h.server) {
		t.Fatalf("key show = %s", out)
	}
	seed, _ := os.ReadFile(p.KeyFile)
	if strings.Contains(out, string(seed)) {
		t.Fatal("key show printed the seed")
	}
}

func TestKeyRegisterWithoutLabelSendsNull(t *testing.T) {
	h := newHarness(t)
	h.mustRun("key", "init")
	h.mustRun("key", "register")
	if !strings.Contains(string(h.calls[1].body), `"label":null`) {
		t.Fatalf("body = %s", h.calls[1].body)
	}
}

func TestKeyRegisterRefusedKeepsBindingNull(t *testing.T) {
	h := newHarness(t)
	h.mustRun("key", "init")
	h.handlers["register_key"] = status(409, `{"error":"too_many_keys","hint":"revoke one"}`)
	if code := h.run("key", "register"); code != 1 || !strings.Contains(h.stderr.String(), "409 too_many_keys: revoke one") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if meta, _ := keystore.LoadMeta(h.paths()); meta.BoundTo != nil {
		t.Fatal("binding stored after a refusal")
	}
}

func TestKeyFileWithGroupOrOtherModeRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		h := newHarness(t)
		h.setupKey()
		if err := os.Chmod(h.paths().KeyFile, mode); err != nil {
			t.Fatal(err)
		}
		if code := h.run("run", "--", "true"); code != 78 || !strings.Contains(h.stderr.String(), "permissions are too open") {
			t.Fatalf("mode %o: run exit %d: %s", mode, code, h.stderr.String())
		}
		if code := h.run("key", "show"); code != 78 {
			t.Fatalf("mode %o: key show exit %d", mode, code)
		}
	}
}

func TestKeyDirectoryFromWhoami(t *testing.T) {
	h := newHarness(t)
	h.agent = "agent_one"
	h.mustRun("key", "init")
	one := h.paths()
	h.agent = "agent_two"
	h.mustRun("key", "init") // no "already exists": a different directory
	two := h.paths()
	if one.KeyFile == two.KeyFile || !strings.Contains(one.KeyFile, "/srv_test/agent_one/") || !strings.Contains(two.KeyFile, "/srv_test/agent_two/") {
		t.Fatalf("key files %s and %s", one.KeyFile, two.KeyFile)
	}
	k1, err1 := keystore.Load(one)
	k2, err2 := keystore.Load(two)
	if err1 != nil || err2 != nil || k1.KeyID() == k2.KeyID() {
		t.Fatalf("keys %v %v %v %v", k1, k2, err1, err2)
	}
	if !strings.HasPrefix(one.KeyFile, h.env["XDG_CONFIG_HOME"]) || !strings.HasPrefix(one.SpoolDir, h.env["XDG_STATE_HOME"]) {
		t.Fatalf("paths not under XDG dirs: %+v", one)
	}
}

func TestWhoamiFailureExits78(t *testing.T) {
	commands := [][]string{
		{"run", "--", "true"}, {"attest", "--file", "x"}, {"flush"},
		{"key", "init"}, {"key", "register"}, {"key", "show"}, {"key", "list"},
		{"key", "revoke", "--reason", "lost"}, {"key", "rotate"},
	}
	for _, args := range commands {
		h := newHarness(t)
		h.whoamiErr = errors.New("raft: whoami failed: not logged in")
		if code := h.run(args...); code != 78 {
			t.Fatalf("%v: exit %d, want 78", args, code)
		}
		if !strings.Contains(h.stderr.String(), "raft integration login --service claim-check") {
			t.Fatalf("%v: no hint: %s", args, h.stderr.String())
		}
	}
}

func TestServiceFlagAndEnvReachInvokeArgv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"default", "", []string{"key", "list"}, "claim-check"},
		{"env", "svc-from-env", []string{"key", "list"}, "svc-from-env"},
		{"command flag beats env", "svc-from-env", []string{"key", "list", "--service", "svc-flag"}, "svc-flag"},
		{"global flag", "", []string{"--service", "svc-global", "key", "list"}, "svc-global"},
		{"run flag", "svc-from-env", []string{"run", "--service=svc-run", "--", "true"}, "svc-run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			if c.env != "" {
				h.env[raft.ServiceEnv] = c.env
			}
			h.services = nil
			h.mustRun(c.args...)
			if len(h.services) == 0 || h.services[len(h.services)-1] != c.want {
				t.Fatalf("services = %v, want %s", h.services, c.want)
			}
			last := h.calls[len(h.calls)-1]
			argv := raft.InvokeArgv(last.service, last.action)
			if argv[2] != c.want || strings.Join(argv, " ") != "integration invoke "+c.want+" "+last.action+" --data-file - --json" {
				t.Fatalf("argv = %v", argv)
			}
		})
	}
	h := newHarness(t)
	if code := h.run("--service", "-x", "key", "list"); code != 64 {
		t.Fatalf("service starting with '-': exit %d, want 64", code)
	}
}

func TestKeyListAndRevoke(t *testing.T) {
	h := newHarness(t)
	key := h.setupKey()
	h.handlers["list_keys"] = status(200, `{"keys":[{"key_id":"`+key.KeyID()+`","public_key":"x","label":"laptop","status":"active","registered_at":"2026-10-06T09:00:00.000Z","revoked_at":null,"revoked_reason":null,"compromised_since":null}]}`)
	h.mustRun("key", "list")
	if !strings.Contains(h.stdout.String(), "*  "+key.KeyID()) || !strings.Contains(h.stdout.String(), "laptop") {
		t.Fatalf("list = %s", h.stdout.String())
	}

	if code := h.run("key", "revoke", "--reason", "stolen"); code != 64 {
		t.Fatalf("bad reason: exit %d", code)
	}
	if code := h.run("key", "revoke", "--reason", "lost", "--compromised-since", "2026-10-01T00:00:00Z"); code != 64 {
		t.Fatalf("compromised-since without compromised: exit %d", code)
	}
	h.calls = nil
	h.mustRun("key", "revoke", "--key-id", "ck_other", "--reason", "compromised", "--compromised-since", "2026-10-01T02:00:00+02:00")
	if got := string(h.calls[0].body); got != `{"compromised_since":"2026-10-01T00:00:00.000Z","key_id":"ck_other","reason":"compromised"}` {
		t.Fatalf("revoke body = %s", got)
	}
	if _, err := keystore.Load(h.paths()); err != nil {
		t.Fatal("revoking another key must keep the local key")
	}
	h.calls = nil
	h.mustRun("key", "revoke", "--reason", "lost") // defaults to the local key
	if got := string(h.calls[0].body); got != `{"key_id":"`+key.KeyID()+`","reason":"lost"}` {
		t.Fatalf("revoke body = %s", got)
	}
	if _, err := os.Stat(h.paths().KeyFile); !os.IsNotExist(err) {
		t.Fatal("the revoked local key was kept")
	}
	h.mustRun("key", "init")
}

func TestKeyRotateRefusesWhileOldKeyReceiptsPending(t *testing.T) {
	h := newHarness(t)
	old := h.setupKey()
	p := h.paths()
	h.handlers["submit_receipt"] = status(503, `{}`)
	h.mustRun("run", "--", "true") // stays pending
	h.calls = nil
	if code := h.run("key", "rotate"); code != 75 || !strings.Contains(h.stderr.String(), "refusing to rotate") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, c := range h.calls {
		if c.action != "submit_receipt" {
			t.Fatalf("rotate changed something: called %s", c.action)
		}
	}
	if len(h.calls) != 1 {
		t.Fatalf("rotate must flush first; calls = %d", len(h.calls))
	}
	if k, err := keystore.Load(p); err != nil || k.KeyID() != old.KeyID() {
		t.Fatal("the old key changed")
	}
	if len(h.spoolFiles(p.SpoolDir)) != 1 {
		t.Fatal("the pending receipt changed")
	}
}

func TestKeyRotateAfterSuccessfulFlush(t *testing.T) {
	h := newHarness(t)
	old := h.setupKey()
	h.handlers["submit_receipt"] = status(503, `{}`)
	h.mustRun("run", "--", "true")
	h.handlers["submit_receipt"] = acceptSubmit(201)
	h.calls = nil
	h.mustRun("key", "rotate")
	var actions []string
	for _, c := range h.calls {
		actions = append(actions, c.action)
	}
	if strings.Join(actions, ",") != "submit_receipt,get_session,register_key,revoke_key" {
		t.Fatalf("actions = %v", actions)
	}
	if got := string(h.calls[3].body); got != `{"key_id":"`+old.KeyID()+`","reason":"rotated"}` {
		t.Fatalf("revoke body = %s", got)
	}
	k, err := keystore.Load(h.paths())
	meta, _ := keystore.LoadMeta(h.paths())
	if err != nil || k.KeyID() == old.KeyID() || meta.BoundTo == nil || meta.KeyID != k.KeyID() {
		t.Fatalf("new key %v meta %+v err %v", k, meta, err)
	}
	if _, err := os.Stat(h.paths().KeyFile + ".old"); !os.IsNotExist(err) {
		t.Fatal("the old private key file was not deleted")
	}
}

func TestKeyRotateForce(t *testing.T) {
	h := newHarness(t)
	old := h.setupKey()
	p := h.paths()
	h.handlers["submit_receipt"] = status(503, `{}`)
	h.mustRun("run", "--", "true")
	h.mustRun("key", "rotate", "--force")
	if k, _ := keystore.Load(p); k.KeyID() == old.KeyID() {
		t.Fatal("--force did not rotate")
	}
	// The next flush gets 403 key_revoked and moves the old receipt away.
	h.handlers["submit_receipt"] = status(403, `{"error":"key_revoked","hint":"revoked"}`)
	h.mustRun("flush")
	if len(h.spoolFiles(p.SpoolDir)) != 0 || len(h.spoolFiles(p.RejectedDir)) != 1 {
		t.Fatal("the old key's receipt was not moved to rejected/")
	}
}

func TestKeyRotateRestoresOldKeyWhenRegisterFails(t *testing.T) {
	h := newHarness(t)
	old := h.setupKey()
	h.handlers["register_key"] = status(409, `{"error":"too_many_keys","hint":"x"}`)
	if code := h.run("key", "rotate"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	k, err := keystore.Load(h.paths())
	meta, _ := keystore.LoadMeta(h.paths())
	if err != nil || k.KeyID() != old.KeyID() || meta.BoundTo == nil {
		t.Fatalf("old key not restored: %v %+v %v", k, meta, err)
	}
	for _, c := range h.calls {
		if c.action == "revoke_key" {
			t.Fatal("revoked the old key although the new one was not registered")
		}
	}
}
