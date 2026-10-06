package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "init", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
}

func TestAttestRecordsFile(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	gitInit(t, h.cwd)
	sub := filepath.Join(h.cwd, "build")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("artifact bytes\n")
	if err := os.WriteFile(filepath.Join(sub, "out.tgz"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun("attest", "--file", "build/out.tgz")
	p, id := payloadOf(t, h.submitted()[0])
	if p.Kind != "attest" || p.Run != nil || p.Attest.Path != "build/out.tgz" || p.Attest.SHA256 != receipt.HashBytes(content) ||
		p.Attest.Bytes != int64(len(content)) || p.Git == nil || !p.Git.Dirty {
		t.Fatalf("payload = %+v attest %+v git %+v", p, p.Attest, p.Git)
	}
	if !strings.Contains(h.stderr.String(), id+" stored") {
		t.Fatalf("line = %s", h.stderr.String())
	}
	// A symlink inside the repository to a file inside it is allowed.
	if err := os.Symlink(filepath.Join(sub, "out.tgz"), filepath.Join(h.cwd, "link.tgz")); err != nil {
		t.Fatal(err)
	}
	h.mustRun("attest", "--file", "link.tgz")
	if p, _ := payloadOf(t, h.submitted()[1]); p.Attest.Path != "link.tgz" || p.Attest.SHA256 != receipt.HashBytes(content) {
		t.Fatalf("attest = %+v", p.Attest)
	}
}

func TestAttestOutsideRepositoryRecordsBaseName(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun("attest", "--file", filepath.Join(dir, "f.txt"))
	if p, _ := payloadOf(t, h.submitted()[0]); p.Attest.Path != "f.txt" || p.Git != nil {
		t.Fatalf("attest = %+v git %+v", p.Attest, p.Git)
	}
}

func TestAttestRefusesDirectory(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	if code := h.run("attest", "--file", t.TempDir()); code != 1 || !strings.Contains(h.stderr.String(), "refusing a directory") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(h.submitted()) != 0 {
		t.Fatal("submitted a receipt for a directory")
	}
}

func TestAttestRefusesDevice(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	if code := h.run("attest", "--file", "/dev/null"); code != 1 || !strings.Contains(h.stderr.String(), "device") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

func TestAttestRefusesSymlinkOutsideRepository(t *testing.T) {
	h := newHarness(t)
	h.setupKey()
	gitInit(t, h.cwd)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.cwd, "link")); err != nil {
		t.Fatal(err)
	}
	if code := h.run("attest", "--file", "link"); code != 1 || !strings.Contains(h.stderr.String(), "outside the repository") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	// Outside a repository the allowed root is the working directory.
	plain := newHarness(t)
	plain.setupKey()
	if err := os.Symlink(outside, filepath.Join(plain.cwd, "link")); err != nil {
		t.Fatal(err)
	}
	if code := plain.run("attest", "--file", "link"); code != 1 || !strings.Contains(plain.stderr.String(), "outside the working directory") {
		t.Fatalf("exit %d: %s", code, plain.stderr.String())
	}
	if len(h.submitted())+len(plain.submitted()) != 0 {
		t.Fatal("submitted a receipt for an outside symlink")
	}
}

func TestAttestUsageAndNoKey(t *testing.T) {
	h := newHarness(t)
	if code := h.run("attest"); code != 64 {
		t.Fatalf("no --file: exit %d", code)
	}
	if code := h.run("attest", "--file", "x"); code != 78 {
		t.Fatalf("no key: exit %d", code)
	}
}

// storedReceipt runs a command and returns the spool-format file path and
// the signer's public key.
func storedReceipt(t *testing.T) (*harness, string, string) {
	t.Helper()
	h := newHarness(t)
	key := h.setupKey()
	h.mustRun("run", "--", "true")
	file := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(file, h.submitted()[0], 0o600); err != nil {
		t.Fatal(err)
	}
	return h, file, receipt.EncodePublicKey(key.PublicKey())
}

func TestVerifySignRoundTrip(t *testing.T) {
	h, file, pub := storedReceipt(t)
	h.calls, h.services = nil, nil
	if code := h.run("verify", file, "--public-key", pub); code != 0 || !strings.HasPrefix(h.stdout.String(), "OK: receipt rcpt_") {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if len(h.calls) != 0 || len(h.services) != 0 {
		t.Fatalf("verify touched Raft: calls %d services %v", len(h.calls), h.services)
	}
}

func TestVerifyStoredReceiptShape(t *testing.T) {
	h, file, pub := storedReceipt(t)
	body, _ := os.ReadFile(file)
	_, id := payloadOf(t, body)
	env := strings.TrimSuffix(strings.TrimPrefix(string(body), `{"receipt":`), "}")
	stored := `{"receipt_id":"` + id + `","envelope":` + env + `,"ledger":{"key":{"public_key":"` + pub + `"}}}`
	path := filepath.Join(t.TempDir(), "stored.json")
	_ = os.WriteFile(path, []byte(stored), 0o600)
	if code := h.run("verify", path); code != 0 || !strings.Contains(h.stderr.String(), "ledger.key.public_key") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	wrongID := strings.Replace(stored, id, "rcpt_aaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
	_ = os.WriteFile(path, []byte(wrongID), 0o600)
	if code := h.run("verify", path, "--public-key", pub); code != 1 || !strings.Contains(h.stderr.String(), "does not match") {
		t.Fatalf("receipt_id mismatch: exit %d: %s", code, h.stderr.String())
	}
}

func TestVerifyTamperedPayloadFails(t *testing.T) {
	h, file, pub := storedReceipt(t)
	body, _ := os.ReadFile(file)
	tampered := strings.Replace(string(body), `"code":0`, `"code":1`, 1)
	if tampered == string(body) {
		t.Fatal("tamper did not apply")
	}
	_ = os.WriteFile(file, []byte(tampered), 0o600)
	if code := h.run("verify", file, "--public-key", pub); code != 1 || !strings.Contains(h.stderr.String(), "signature does not verify") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

func TestVerifyRejectsDuplicateKeysAndWrongKey(t *testing.T) {
	h, file, pub := storedReceipt(t)
	body, _ := os.ReadFile(file)
	dup := strings.Replace(string(body), `"kind":"run"`, `"kind":"run","kind":"run"`, 1)
	_ = os.WriteFile(file, []byte(dup), 0o600)
	if code := h.run("verify", file, "--public-key", pub); code != 1 || !strings.Contains(h.stderr.String(), "duplicate") {
		t.Fatalf("duplicate key: exit %d: %s", code, h.stderr.String())
	}
	_ = os.WriteFile(file, body, 0o600)
	other := receipt.EncodePublicKey(make([]byte, 32))
	if code := h.run("verify", file, "--public-key", other); code != 1 {
		t.Fatalf("wrong key: exit %d", code)
	}
	if code := h.run("verify", file); code != 64 {
		t.Fatalf("no key available: exit %d, want 64", code)
	}
}

func TestVerifyRegistrationStatement(t *testing.T) {
	h := newHarness(t)
	h.mustRun("key", "init")
	h.mustRun("key", "register")
	file := filepath.Join(t.TempDir(), "reg.json")
	_ = os.WriteFile(file, h.calls[1].body, 0o600)
	if code := h.run("verify", file); code != 0 || !strings.Contains(h.stdout.String(), "registration statement") {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
}
