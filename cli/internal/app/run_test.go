package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func TestRunPassThroughByteIdentical(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	// Every byte value, invalid UTF-8, CR, NUL and ANSI included.
	var raw bytes.Buffer
	for i := 0; i < 40; i++ {
		for b := 0; b < 256; b++ {
			raw.WriteByte(byte(b))
		}
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	errOut := filepath.Join(t.TempDir(), "err.bin")
	if err := os.WriteFile(out, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errOut, []byte("err\x1b[31m\r\nline\x00\xff"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := h.run("run", "--quiet", "--", "sh", "-c", `cat "$1"; cat "$2" >&2`, "sh", out, errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !bytes.Equal(h.stdout.Bytes(), raw.Bytes()) {
		t.Fatal("stdout differs from the child's")
	}
	if h.stderr.String() != "err\x1b[31m\r\nline\x00\xff" {
		t.Fatalf("stderr = %q (--quiet must add nothing)", h.stderr.String())
	}
	p, _ := payloadOf(t, h.submitted()[0])
	sum := sha256.Sum256(raw.Bytes())
	if p.Run.Stdout.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || p.Run.Stdout.Bytes != int64(raw.Len()) {
		t.Fatalf("stdout hash/bytes = %s %d", p.Run.Stdout.SHA256, p.Run.Stdout.Bytes)
	}
	if p.Run.Stderr.Tail != "err\nline�" {
		t.Fatalf("stderr tail = %q", p.Run.Stderr.Tail)
	}
}

func TestRunChildExitCodePassesThrough(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	if code := h.run("run", "--", "sh", "-c", "exit 3"); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
	p, id := payloadOf(t, h.submitted()[0])
	if p.Run.Exit.Code == nil || *p.Run.Exit.Code != 3 || p.Run.Exit.Signal != nil {
		t.Fatalf("exit = %+v", p.Run.Exit)
	}
	if !strings.HasPrefix(h.stderr.String(), "claim-check: "+id+" stored") {
		t.Fatalf("stderr line = %q", h.stderr.String())
	}
}

func TestRunSignalExit128PlusN(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	if code := h.run("run", "--", "sh", "-c", "kill -TERM $$"); code != 143 {
		t.Fatalf("exit %d, want 143", code)
	}
	p, _ := payloadOf(t, h.submitted()[0])
	if p.Run.Exit.Code != nil || p.Run.Exit.Signal == nil || *p.Run.Exit.Signal != "SIGTERM" {
		t.Fatalf("exit = %+v", p.Run.Exit)
	}
}

func TestRunCommandNotFound127(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	if code := h.run("run", "--", "claim-check-no-such-command-xyz"); code != 127 {
		t.Fatalf("exit %d, want 127", code)
	}
	if code := h.run("run", "--", filepath.Join(t.TempDir(), "missing")); code != 127 {
		t.Fatalf("exit %d, want 127", code)
	}
	if len(h.submitted()) != 0 || len(h.spoolFiles(h.paths().SpoolDir)) != 0 {
		t.Fatal("a receipt was made although nothing ran")
	}
}

func TestRunNotExecutable126(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	script := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run("run", "--", script); code != 126 {
		t.Fatalf("exit %d, want 126", code)
	}
	if code := h.run("run", "--", t.TempDir()); code != 126 {
		t.Fatalf("directory: exit %d, want 126", code)
	}
	if len(h.submitted()) != 0 {
		t.Fatal("a receipt was made although nothing ran")
	}
}

func TestRunNoKey78(t *testing.T) {
	h := newHarness(t)
	marker := filepath.Join(t.TempDir(), "ran")
	if code := h.run("run", "--", "touch", marker); code != 78 {
		t.Fatalf("exit %d, want 78", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran without a key")
	}
	if !strings.Contains(h.stderr.String(), "key init") {
		t.Fatalf("no hint: %q", h.stderr.String())
	}
}

func TestRunUnregisteredKey78(t *testing.T) {
	h := newHarness(t)
	h.mustRun("key", "init")
	if code := h.run("run", "--", "true"); code != 78 {
		t.Fatalf("exit %d, want 78", code)
	}
	if !strings.Contains(h.stderr.String(), "key register") {
		t.Fatalf("no hint: %q", h.stderr.String())
	}
}

func TestRunUsage64(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	for _, args := range [][]string{{"run"}, {"run", "--bogus", "--", "true"}, {"run", "--redact-arg", "5", "--", "true"}, {"run", "--redact-arg", "-1", "--", "true"}} {
		if code := h.run(args...); code != 64 {
			t.Fatalf("%v: exit %d, want 64", args, code)
		}
	}
	// argv over the 8 KB cap is refused before the child starts.
	if code := h.run("run", "--", "echo", strings.Repeat("a", 9000)); code != 64 {
		t.Fatalf("oversize argv: exit %d, want 64", code)
	}
}

func TestRunHashesFullOutputTailRedactedAndCapped(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	token := "ghp_" + strings.Repeat("Q1w2", 9)
	full := strings.Repeat("0123456789abcdef", 1000) + "\nleaked " + token + "\ndone\n"
	file := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(file, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun("run", "--", "cat", file)
	if h.stdout.String() != full {
		t.Fatal("stdout was altered; redaction must only touch the tail")
	}
	p, _ := payloadOf(t, h.submitted()[0])
	s := p.Run.Stdout
	if s.SHA256 != receipt.HashBytes([]byte(full)) || s.Bytes != int64(len(full)) {
		t.Fatalf("hash must cover the full unredacted output: %s %d", s.SHA256, s.Bytes)
	}
	if len(s.Tail) > 2048 || !s.TailTruncated || s.TailRedactions != 1 {
		t.Fatalf("tail len %d truncated %v redactions %d", len(s.Tail), s.TailTruncated, s.TailRedactions)
	}
	if strings.Contains(s.Tail, token) || !strings.HasSuffix(s.Tail, "leaked [REDACTED:known_token]\ndone\n") {
		t.Fatalf("tail end = %q", s.Tail[len(s.Tail)-60:])
	}
}

func TestRunArgvRedaction(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	h.mustRun("run", "--redact-arg", "2", "--", "echo", "--token=abc", "positional-secret", "--password", "hunter2", "plain")
	if h.stdout.String() != "--token=abc positional-secret --password hunter2 plain\n" {
		t.Fatalf("the child must see the real argv: %q", h.stdout.String())
	}
	p, _ := payloadOf(t, h.submitted()[0])
	want := []string{"echo", "--token=[REDACTED:sensitive_flag]", "[REDACTED:redact_arg]", "--password", "[REDACTED:sensitive_flag]", "plain"}
	if strings.Join(p.Run.Argv, " ") != strings.Join(want, " ") || p.Run.ArgvRedactions != 3 {
		t.Fatalf("argv = %q (%d)", p.Run.Argv, p.Run.ArgvRedactions)
	}
}

func TestRunRecordsSchemaFields(t *testing.T) {
	h := newHarness(t)
	key := h.setupKey()
	h.mustRun("run", "--", "true")
	p, _ := payloadOf(t, h.submitted()[0])
	if p.Schema != receipt.SchemaReceipt || p.Kind != "run" || p.KeyID != key.KeyID() ||
		p.BoundTo.ServerID != h.server || p.BoundTo.PrincipalID != h.agent || p.CLI.Name != "claim-check" ||
		p.CLI.Version != "2.0.0-test" || p.Git != nil || p.Run.CwdRel != nil || p.Attest != nil || len(p.Nonce) != 22 {
		t.Fatalf("payload = %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRunSpoolWrittenBeforeSubmit(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	p := h.paths()
	sawFile := false
	h.handlers["submit_receipt"] = func(body []byte) (int, []byte, error) {
		_, id := payloadOf(t, body)
		data, err := os.ReadFile(p.SpoolFile(id))
		sawFile = err == nil && bytes.Equal(data, body)
		if info, err := os.Stat(p.SpoolFile(id)); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("spool file mode: %v %v", info, err)
		}
		return acceptSubmit(201)(body)
	}
	h.mustRun("run", "--", "true")
	if !sawFile {
		t.Fatal("the spool file did not exist (with the body) when Invoke was called")
	}
	if len(h.spoolFiles(p.SpoolDir)) != 0 {
		t.Fatal("the spool file was not removed after 201 with a matching receipt_id")
	}
}

func TestRunRequireReceipt(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	h.handlers["submit_receipt"] = func([]byte) (int, []byte, error) { return 503, []byte(`{}`), nil }
	if code := h.run("run", "--require-receipt", "--", "true"); code != 75 {
		t.Fatalf("exit %d, want 75", code)
	}
	if !strings.Contains(h.stderr.String(), "exiting 75") {
		t.Fatalf("line = %q", h.stderr.String())
	}
	if code := h.run("run", "--require-receipt", "--", "sh", "-c", "exit 4"); code != 4 {
		t.Fatalf("exit %d, want 4", code)
	}
	if !strings.Contains(h.stderr.String(), "passing through the child's exit code 4") {
		t.Fatalf("line = %q", h.stderr.String())
	}
	h.handlers["submit_receipt"] = acceptSubmit(201)
	if code := h.run("run", "--require-receipt", "--", "true"); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	// Without --require-receipt a failed submit never changes the exit code.
	h.handlers["submit_receipt"] = func([]byte) (int, []byte, error) { return 503, []byte(`{}`), nil }
	if code := h.run("run", "--", "true"); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
}

// floodThenExit3 writes far more than a pipe buffer, then exits 3. It only
// exits 3 if it never gets SIGPIPE.
var floodThenExit3 = []string{"sh", "-c", `i=0; while [ $i -lt 200000 ]; do echo line$i; i=$((i+1)); done; exit 3`}

// checkSIGPIPEReceipt checks that a receipt with exit.signal SIGPIPE was
// spooled and submitted, and removed after the 201.
func checkSIGPIPEReceipt(t *testing.T, h *harness, code int) {
	t.Helper()
	if code != 141 {
		t.Fatalf("exit %d, want 141 (128 + SIGPIPE, the child's signal)\nstderr: %s", code, h.stderr.String())
	}
	subs := h.submitted()
	if len(subs) != 1 {
		t.Fatalf("%d receipts submitted, want 1", len(subs))
	}
	p, id := payloadOf(t, subs[0])
	if p.Run.Exit.Code != nil || p.Run.Exit.Signal == nil || *p.Run.Exit.Signal != "SIGPIPE" {
		t.Fatalf("exit = %+v", p.Run.Exit)
	}
	if !strings.HasPrefix(h.stderr.String(), "claim-check: "+id+" stored") {
		t.Fatalf("stderr line = %q", h.stderr.String())
	}
}

func TestRunStdoutClosedRecordsChildSIGPIPE(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	h.out = w
	sawFile := false
	h.handlers["submit_receipt"] = func(body []byte) (int, []byte, error) {
		_, id := payloadOf(t, body)
		_, err := os.Stat(h.paths().SpoolFile(id))
		sawFile = err == nil
		return acceptSubmit(201)(body)
	}
	checkSIGPIPEReceipt(t, h, h.run(append([]string{"run", "--"}, floodThenExit3...)...))
	if !sawFile {
		t.Fatal("the receipt was not spooled before submit")
	}
}

// The Go runtime only kills a program for writing to a closed fd 1 or 2, so
// this test runs claim-check in a subprocess whose real stdout is a pipe
// with no reader. The helper reports through its exit code and a file.
func TestRunClosedProcessStdoutDoesNotKillCLI(t *testing.T) {
	if os.Getenv("CLAIM_CHECK_SIGPIPE_HELPER") == "1" {
		h := newHarness(t)
		h.setupKey()
		h.out = os.Stdout
		code := h.run(append([]string{"run", "--"}, floodThenExit3...)...)
		var sig string
		if subs := h.submitted(); len(subs) == 1 {
			if p, _ := payloadOf(t, subs[0]); p.Run.Exit.Signal != nil {
				sig = *p.Run.Exit.Signal
			}
		}
		report := fmt.Sprintf("%d %d %s", code, len(h.submitted()), sig)
		_ = os.WriteFile(os.Getenv("CLAIM_CHECK_SIGPIPE_REPORT"), []byte(report), 0o600)
		os.Exit(code) // before the test framework writes to the closed stdout
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	report := filepath.Join(t.TempDir(), "report")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunClosedProcessStdoutDoesNotKillCLI$")
	cmd.Env = append(os.Environ(), "CLAIM_CHECK_SIGPIPE_HELPER=1", "CLAIM_CHECK_SIGPIPE_REPORT="+report)
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 141 {
		t.Fatalf("claim-check %v, want exit 141 (killed by a signal means the CLI itself died)\nstderr: %s", cmd.ProcessState, stderr.String())
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "141 1 SIGPIPE" {
		t.Fatalf("report = %q, want exit 141, 1 receipt submitted, exit.signal SIGPIPE", data)
	}
}

func TestForwardSignal(t *testing.T) {
	cases := []struct {
		name                   string
		sig                    os.Signal
		child, cli, foreground int
		want                   bool
	}{
		{"SIGINT, same group, foreground", syscall.SIGINT, 100, 100, 100, false},
		{"SIGINT, child in another group", syscall.SIGINT, 200, 100, 100, true},
		{"SIGINT, foreground unknown", syscall.SIGINT, 100, 100, -1, true},
		{"SIGINT, child group unknown", syscall.SIGINT, -1, 100, 100, true},
		{"SIGINT, CLI group not foreground", syscall.SIGINT, 100, 100, 300, true},
		{"SIGTERM, same group, foreground", syscall.SIGTERM, 100, 100, 100, true},
		{"SIGHUP, same group, foreground", syscall.SIGHUP, 100, 100, 100, true},
		{"SIGQUIT, same group, foreground", syscall.SIGQUIT, 100, 100, 100, true},
	}
	for _, c := range cases {
		if got := forwardSignal(c.sig, c.child, c.cli, c.foreground); got != c.want {
			t.Errorf("%s: forwardSignal = %v, want %v", c.name, got, c.want)
		}
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestRunMasksHomeInTailsKeepsRawHash(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	home := h.home
	h.mustRun("run", "--", "sh", "-c", `printf '%s/proj/a.txt\n%s/x\n%sby/y\n' "$1" "$1" "$1"; printf 'err %s\n' "$1" >&2`, "sh", home)
	raw := home + "/proj/a.txt\n" + home + "/x\n" + home + "by/y\n"
	if h.stdout.String() != raw {
		t.Fatalf("the child's stdout was altered: %q", h.stdout.String())
	}
	p, _ := payloadOf(t, h.submitted()[0])
	s := p.Run.Stdout
	if s.SHA256 != receipt.HashBytes([]byte(raw)) || s.Bytes != int64(len(raw)) {
		t.Fatalf("hash must cover the raw output: %s %d", s.SHA256, s.Bytes)
	}
	if want := "~/proj/a.txt\n~/x\n" + home + "by/y\n"; s.Tail != want || s.TailRedactions != 2 || s.TailTruncated {
		t.Fatalf("stdout tail = %q (%d, truncated %v), want %q (2)", s.Tail, s.TailRedactions, s.TailTruncated, want)
	}
	rawErr := "err " + home + "\n"
	e := p.Run.Stderr
	if e.SHA256 != receipt.HashBytes([]byte(rawErr)) || e.Bytes != int64(len(rawErr)) || e.Tail != "err ~\n" || e.TailRedactions != 1 {
		t.Fatalf("stderr = %+v", e)
	}
}

func TestRunMasksHomeInArgv(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	h.home = "/Users/bob"
	token := "ghp_" + strings.Repeat("Q1w2", 9)
	h.mustRun("run", "--", "echo", "/Users/bob/x", "/Users/bobby/y", "/Users/bob/k "+token, "file:///Users/bob/r.git", "plain")
	if h.stdout.String() != "/Users/bob/x /Users/bobby/y /Users/bob/k "+token+" file:///Users/bob/r.git plain\n" {
		t.Fatalf("the child must see the real argv: %q", h.stdout.String())
	}
	p, _ := payloadOf(t, h.submitted()[0])
	want := []string{"echo", "~/x", "/Users/bobby/y", "~/k [REDACTED:known_token]", "file://~/r.git", "plain"}
	if strings.Join(p.Run.Argv, "|") != strings.Join(want, "|") || p.Run.ArgvRedactions != 3 {
		t.Fatalf("argv = %q (%d), want %q (3)", p.Run.Argv, p.Run.ArgvRedactions, want)
	}
}

func TestRunProbeSeesHomeMaskedArgv(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	h.home = "/" + strings.Repeat("h", 1000)
	args := []string{"run", "--", "true"}
	for i := 0; i < 9; i++ {
		args = append(args, h.home+"/a")
	}
	// The raw argv is over the 8 KB cap; the masked argv is far under it.
	h.mustRun(args...)
	p, _ := payloadOf(t, h.submitted()[0])
	if len(p.Run.Argv) != 10 || p.Run.Argv[1] != "~/a" || p.Run.ArgvRedactions != 9 {
		t.Fatalf("argv = %q (%d)", p.Run.Argv, p.Run.ArgvRedactions)
	}
}

func TestMasksHomeInRemoteURL(t *testing.T) {
	for _, c := range []struct{ name, remote, want string }{
		{"local path", "%s/repos/x.git", "~/repos/x.git"},
		{"file URL", "file://%s/repos/x.git", "file://~/repos/x.git"},
		{"lookalike prefix", "%sby/repos/x.git", "%sby/repos/x.git"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			gitInit(t, h.cwd)
			gitIn(t, h.cwd, "remote", "add", "origin", strings.ReplaceAll(c.remote, "%s", h.home))
			want := strings.ReplaceAll(c.want, "%s", h.home)
			if err := os.WriteFile(filepath.Join(h.cwd, "a.txt"), []byte("a"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.mustRun("run", "--", "true")
			h.mustRun("attest", "--file", "a.txt")
			subs := h.submitted()
			for i, kind := range []string{"run", "attest"} {
				p, _ := payloadOf(t, subs[i])
				if p.Git == nil || p.Git.RemoteURL == nil || *p.Git.RemoteURL != want {
					t.Fatalf("%s: git = %+v, want remote_url %q", kind, p.Git, want)
				}
			}
		})
	}
}

func TestRunHomeEmptyOrUnreadableLeavesUnmasked(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(h *harness)
	}{
		{"empty home", func(h *harness) { h.home = "" }},
		{"lookup fails", func(h *harness) { h.homeErr = fmt.Errorf("no home") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setupKey()
			home := h.home
			c.set(h)
			gitInit(t, h.cwd)
			gitIn(t, h.cwd, "remote", "add", "origin", home+"/repos/x.git")
			h.mustRun("run", "--", "echo", home+"/x")
			p, _ := payloadOf(t, h.submitted()[0])
			if p.Run.Argv[1] != home+"/x" || p.Run.ArgvRedactions != 0 {
				t.Fatalf("argv = %q (%d)", p.Run.Argv, p.Run.ArgvRedactions)
			}
			if p.Run.Stdout.Tail != home+"/x\n" || p.Run.Stdout.TailRedactions != 0 {
				t.Fatalf("tail = %q (%d)", p.Run.Stdout.Tail, p.Run.Stdout.TailRedactions)
			}
			if p.Git == nil || p.Git.RemoteURL == nil || *p.Git.RemoteURL != home+"/repos/x.git" {
				t.Fatalf("git = %+v", p.Git)
			}
		})
	}
}
