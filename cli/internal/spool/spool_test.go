package spool

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func setup(t *testing.T) (keystore.Paths, *keystore.Key) {
	t.Helper()
	home := t.TempDir()
	p, err := keystore.Resolve(func(k string) (string, bool) {
		if k == "HOME" {
			return home, true
		}
		return "", false
	}, "srv_1", "agent_1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := keystore.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return p, key
}

func envelope(t *testing.T, key *keystore.Key, signedAt time.Time, nonce string) receipt.Envelope {
	t.Helper()
	h := receipt.Header{Nonce: nonce, KeyID: key.KeyID(), BoundTo: receipt.BoundTo{ServerID: "srv_1", PrincipalID: "agent_1"},
		CLI: receipt.CLI{Version: "t", OS: "linux", Arch: "amd64"}, SignedAt: signedAt}
	p, err := receipt.NewAttestPayload(h, receipt.Attest{Path: "a", SHA256: receipt.HashBytes(nil), ObservedAt: receipt.FormatTime(signedAt)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := receipt.Sign(key, p)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestWriteLayoutAndMode(t *testing.T) {
	p, key := setup(t)
	env := envelope(t, key, time.Now(), "n1")
	e, err := Write(p, env)
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != filepath.Join(p.SpoolDir, env.ReceiptID()+".json") || e.ID != env.ReceiptID() || e.KeyID != key.KeyID() {
		t.Fatalf("entry = %+v", e)
	}
	info, err := os.Stat(e.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", info.Mode(), err)
	}
	data, _ := os.ReadFile(e.Path)
	v, err := jcs.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	inner, ok := v.(map[string]any)["receipt"].(map[string]any)
	if !ok || inner["payload"] == nil || inner["signature"] == nil || len(v.(map[string]any)) != 1 {
		t.Fatalf("spool file shape: %s", data)
	}
	if canon, _ := jcs.Canonicalize(data); !bytes.Equal(canon, data) {
		t.Fatal("spool file is not JCS")
	}
	if dir, _ := os.Stat(p.SpoolDir); dir.Mode().Perm() != 0o700 {
		t.Fatalf("spool dir mode %v", dir.Mode())
	}
}

func TestListOldestFirstAndBadFiles(t *testing.T) {
	p, key := setup(t)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, d := range []time.Duration{3 * time.Hour, time.Hour, 2 * time.Hour} {
		if _, err := Write(p, envelope(t, key, base.Add(d), "n"+string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(p.SpoolDir, "rcpt_garbage.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, bad, err := List(p)
	if err != nil || len(entries) != 3 || len(bad) != 1 {
		t.Fatalf("entries %d bad %d err %v", len(entries), len(bad), err)
	}
	for i, want := range []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour} {
		if !entries[i].SignedAt.Equal(base.Add(want)) {
			t.Fatalf("entry %d signed %v", i, entries[i].SignedAt)
		}
	}
}

func TestRejectAndPurge(t *testing.T) {
	p, key := setup(t)
	e, err := Write(p, envelope(t, key, time.Now(), "n1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	if err := Reject(p, e, Rejection{Status: 403, Error: "key_revoked", Hint: "h"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.Path); !os.IsNotExist(err) {
		t.Fatal("pending file still present")
	}
	data, err := os.ReadFile(p.RejectedFile(e.ID))
	if err != nil || !strings.Contains(string(data), `"error":"key_revoked"`) || !strings.Contains(string(data), `"receipt":{`) {
		t.Fatalf("rejected file: %s %v", data, err)
	}
	if n, _ := PurgeRejected(p, now.Add(29*24*time.Hour)); n != 0 {
		t.Fatal("purged too early")
	}
	if n, _ := PurgeRejected(p, now.Add(31*24*time.Hour)); n != 1 {
		t.Fatal("not purged after 30 days")
	}
}
