package raft

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeBin writes a shell script standing in for `raft`. It records its argv
// (one per line) and its stdin, then prints stdout and exits with code. The
// real raft is never run.
func fakeBin(t *testing.T, stdout, stderr string, code int) (bin, argvFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argvFile, stdinFile = filepath.Join(dir, "argv"), filepath.Join(dir, "stdin")
	out, errf := filepath.Join(dir, "out"), filepath.Join(dir, "err")
	if err := os.WriteFile(out, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errf, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + argvFile + "'\n" +
		"cat > '" + stdinFile + "'\n" +
		"cat '" + out + "'\ncat '" + errf + "' >&2\n" +
		"exit " + strconv.Itoa(code) + "\n"
	bin = filepath.Join(dir, "fake-raft")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argvFile, stdinFile
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestResolveServicePrecedence(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	if got := ResolveService("flag-svc", env(map[string]string{ServiceEnv: "env-svc"})); got != "flag-svc" {
		t.Fatalf("flag: %q", got)
	}
	if got := ResolveService("", env(map[string]string{ServiceEnv: "env-svc"})); got != "env-svc" {
		t.Fatalf("env: %q", got)
	}
	if got := ResolveService("", env(nil)); got != DefaultService {
		t.Fatalf("default: %q", got)
	}
}

func TestInvokeArgvCarriesServiceNotBody(t *testing.T) {
	got := strings.Join(InvokeArgv("my-svc", "submit_receipt"), " ")
	if got != "integration invoke my-svc submit_receipt --data-file - --json" {
		t.Fatalf("argv = %q", got)
	}
}

func TestInvokeBodyOnStdinNotArgv(t *testing.T) {
	out := `{"ok":true,"data":{"service":"svc-x","action":"submit_receipt","status":201,"result":{"receipt_id":"rcpt_x"}}}`
	bin, argvFile, stdinFile := fakeBin(t, out, "", 0)
	c := &CLI{Bin: bin, Service: "svc-x", Timeout: 10 * time.Second}
	body := []byte(`{"receipt":{"payload":{"marker":"BODY-MARKER"}}}`)
	status, result, err := c.Invoke("submit_receipt", body)
	if err != nil || status != 201 || string(result) != `{"receipt_id":"rcpt_x"}` {
		t.Fatalf("Invoke = %d %s %v", status, result, err)
	}
	argv := readLines(t, argvFile)
	if strings.Join(argv, " ") != "integration invoke svc-x submit_receipt --data-file - --json" {
		t.Fatalf("argv = %q", argv)
	}
	for _, a := range argv {
		if strings.Contains(a, "BODY-MARKER") {
			t.Fatal("body leaked into argv")
		}
	}
	if stdin, _ := os.ReadFile(stdinFile); string(stdin) != string(body) {
		t.Fatalf("stdin = %q", stdin)
	}
}

func TestInvokeNonZeroExitWithShapeStillParses(t *testing.T) {
	out := `{"ok":false,"data":{"service":"s","action":"a","status":403,"result":{"error":"key_revoked","hint":"h"}}}`
	bin, _, _ := fakeBin(t, out, "", 1)
	status, result, err := (&CLI{Bin: bin, Service: "s"}).Invoke("a", []byte("{}"))
	if err != nil || status != 403 || !strings.Contains(string(result), "key_revoked") {
		t.Fatalf("got %d %s %v", status, result, err)
	}
}

func TestInvokeFailures(t *testing.T) {
	cases := []struct {
		name           string
		stdout, stderr string
		code           int
		want           error
	}{
		{"unparseable output", "not json", "", 0, ErrUnknownOutcome},
		{"missing status", `{"ok":true,"data":{"result":{}}}`, "", 0, ErrUnknownOutcome},
		{"missing result", `{"ok":true,"data":{"status":201}}`, "", 0, ErrUnknownOutcome},
		{"float status", `{"ok":true,"data":{"status":201.5,"result":{}}}`, "", 0, ErrUnknownOutcome},
		{"unknown command", "", "Error: unknown command \"integration\" for \"raft\"", 1, ErrNotInstalled},
		{"not logged in", "", "error: not logged in", 1, ErrNotLoggedIn},
		{"other failure", "", "boom", 2, ErrUnknownOutcome},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bin, _, _ := fakeBin(t, c.stdout, c.stderr, c.code)
			_, _, err := (&CLI{Bin: bin, Service: "s"}).Invoke("a", []byte("{}"))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestInvokeRaftMissing(t *testing.T) {
	_, _, err := (&CLI{Bin: filepath.Join(t.TempDir(), "no-such-raft"), Service: "s"}).Invoke("a", nil)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvokeTimeout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "slow-raft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := (&CLI{Bin: bin, Service: "s", Timeout: 200 * time.Millisecond}).Invoke("a", nil)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestWhoami(t *testing.T) {
	out := `{"ok":true,"data":{"agent":{"id":"agent_1","name":"a"},"server":{"id":"srv_1","slug":"s"}}}`
	bin, argvFile, _ := fakeBin(t, out, "", 0)
	srv, agent, err := (&CLI{Bin: bin}).Whoami()
	if err != nil || srv != "srv_1" || agent != "agent_1" {
		t.Fatalf("Whoami = %q %q %v", srv, agent, err)
	}
	if got := strings.Join(readLines(t, argvFile), " "); got != "auth whoami" {
		t.Fatalf("argv = %q", got)
	}
}

func TestWhoamiFailures(t *testing.T) {
	for name, c := range map[string]struct {
		out  string
		code int
	}{
		"not ok":        {`{"ok":false,"error":"not logged in"}`, 1},
		"missing agent": {`{"ok":true,"data":{"server":{"id":"srv_1"}}}`, 0},
		"garbage":       {"???", 0},
	} {
		t.Run(name, func(t *testing.T) {
			bin, _, _ := fakeBin(t, c.out, "", c.code)
			if _, _, err := (&CLI{Bin: bin}).Whoami(); !errors.Is(err, ErrWhoami) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
