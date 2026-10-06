package keystore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func envOf(m map[string]string) LookupEnv {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func tempPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p, err := Resolve(envOf(map[string]string{"HOME": root}), "srv_1", "agent_1")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestResolveXDGSetVersusUnset(t *testing.T) {
	set, err := Resolve(envOf(map[string]string{
		"HOME": "/home/u", "XDG_CONFIG_HOME": "/xdg/config", "XDG_STATE_HOME": "/xdg/state/",
	}), "srv_1", "agent_1")
	if err != nil {
		t.Fatal(err)
	}
	if set.KeyFile != "/xdg/config/claim-check/srv_1/agent_1/key/ed25519" ||
		set.MetaFile != "/xdg/config/claim-check/srv_1/agent_1/key/key.json" ||
		set.SpoolDir != "/xdg/state/claim-check/srv_1/agent_1/spool" ||
		set.RejectedDir != "/xdg/state/claim-check/srv_1/agent_1/spool/rejected" {
		t.Errorf("XDG set: %+v", set)
	}
	unset, err := Resolve(envOf(map[string]string{"HOME": "/home/u"}), "srv_1", "agent_1")
	if err != nil {
		t.Fatal(err)
	}
	if unset.ConfigDir != "/home/u/.config/claim-check/srv_1/agent_1" ||
		unset.StateDir != "/home/u/.local/state/claim-check/srv_1/agent_1" {
		t.Errorf("XDG unset: %+v", unset)
	}
	// Empty and relative XDG values are ignored, as the XDG spec says.
	rel, err := Resolve(envOf(map[string]string{
		"HOME": "/home/u", "XDG_CONFIG_HOME": "rel/config", "XDG_STATE_HOME": "",
	}), "srv_1", "agent_1")
	if err != nil || rel != unset {
		t.Errorf("relative XDG: %+v, %v", rel, err)
	}
	if got := unset.SpoolFile("rcpt_x"); got != "/home/u/.local/state/claim-check/srv_1/agent_1/spool/rcpt_x.json" {
		t.Errorf("SpoolFile = %s", got)
	}
}

func TestResolveNoHome(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"HOME": ""},
		{"HOME": "relative"},
		{"XDG_CONFIG_HOME": "/xdg/config"}, // state still has no base
	} {
		if _, err := Resolve(envOf(env), "srv_1", "agent_1"); !errors.Is(err, ErrNoHome) {
			t.Errorf("env %v: %v, want ErrNoHome", env, err)
		}
	}
	both := map[string]string{"XDG_CONFIG_HOME": "/c", "XDG_STATE_HOME": "/s"}
	if _, err := Resolve(envOf(both), "srv_1", "agent_1"); err != nil {
		t.Errorf("both XDG set without HOME: %v", err)
	}
}

func TestTwoPairsTwoDirectories(t *testing.T) {
	env := envOf(map[string]string{"HOME": "/home/u"})
	seen := map[string]string{}
	for _, pair := range [][2]string{{"srv_1", "agent_1"}, {"srv_1", "agent_2"}, {"srv_2", "agent_1"}} {
		p, err := Resolve(env, pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{p.ConfigDir, p.StateDir} {
			if prev, dup := seen[dir]; dup {
				t.Errorf("%v and %s share %s", pair, prev, dir)
			}
			seen[dir] = fmt.Sprint(pair)
		}
	}
}

func TestResolveRejectsUnsafeIDs(t *testing.T) {
	env := envOf(map[string]string{"HOME": "/home/u"})
	for _, id := range []string{"", ".", "..", ".hidden", "a/b", `a\b`, "a\x00b"} {
		if _, err := Resolve(env, id, "agent_1"); !errors.Is(err, ErrBadID) {
			t.Errorf("server_id %q: %v, want ErrBadID", id, err)
		}
		if _, err := Resolve(env, "srv_1", id); !errors.Is(err, ErrBadID) {
			t.Errorf("agent_id %q: %v, want ErrBadID", id, err)
		}
	}
}

func TestGenerateModesAndLoad(t *testing.T) {
	p := tempPaths(t)
	key, err := Generate(p, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureStateDirs(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Dir(filepath.Dir(p.ConfigDir)), filepath.Dir(p.ConfigDir), p.ConfigDir, p.KeyDir,
		filepath.Dir(filepath.Dir(p.StateDir)), filepath.Dir(p.StateDir), p.StateDir, p.SpoolDir, p.RejectedDir,
	} {
		if m := mode(t, dir); m != DirMode {
			t.Errorf("%s mode %04o, want 0700", dir, m)
		}
	}
	for _, f := range []string{p.KeyFile, p.MetaFile} {
		if m := mode(t, f); m != FileMode {
			t.Errorf("%s mode %04o, want 0600", f, m)
		}
	}
	if info, _ := os.Stat(p.KeyFile); info.Size() != 32 {
		t.Errorf("key file is %d bytes, want 32 raw seed bytes", info.Size())
	}

	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PublicKey().Equal(key.PublicKey()) || loaded.KeyID() != key.KeyID() {
		t.Error("loaded key differs from generated key")
	}
	meta, err := LoadMeta(p)
	if err != nil {
		t.Fatal(err)
	}
	if meta.KeyID != key.KeyID() || meta.PublicKey != receipt.EncodePublicKey(key.PublicKey()) || meta.BoundTo != nil {
		t.Errorf("meta = %+v", meta)
	}

	// Binding is stored and read back; the file stays 0600.
	meta.BoundTo = &receipt.BoundTo{ServerID: "srv_1", PrincipalID: "agent_1"}
	if err := SaveMeta(p, meta); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, p.MetaFile); m != FileMode {
		t.Errorf("key.json mode after SaveMeta %04o", m)
	}
	again, err := LoadMeta(p)
	if err != nil || again.BoundTo == nil || *again.BoundTo != *meta.BoundTo {
		t.Errorf("LoadMeta after binding = %+v, %v", again, err)
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(p.KeyDir)
	if len(entries) != 2 {
		t.Errorf("key dir has %d entries, want 2", len(entries))
	}
}

func TestGenerateTightensExistingDirs(t *testing.T) {
	p := tempPaths(t)
	if err := os.MkdirAll(p.KeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.KeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(p, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, p.KeyDir); m != DirMode {
		t.Errorf("key dir mode %04o, want 0700", m)
	}
}

func TestGenerateRefusesExistingKey(t *testing.T) {
	p := tempPaths(t)
	first, err := Generate(p, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p.KeyFile)
	if _, err := Generate(p, rand.Reader); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate: %v, want ErrKeyExists", err)
	}
	after, _ := os.ReadFile(p.KeyFile)
	if !bytes.Equal(before, after) {
		t.Error("existing key file was changed")
	}
	if k, _ := Load(p); k.KeyID() != first.KeyID() {
		t.Error("key changed")
	}
}

func TestLoadRefusesLooseModes(t *testing.T) {
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o606, 0o610, 0o601, 0o700} {
		t.Run(fmt.Sprintf("%04o", m), func(t *testing.T) {
			p := tempPaths(t)
			if _, err := Generate(p, rand.Reader); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p.KeyFile, m); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if m&0o077 != 0 {
				if !errors.Is(err, ErrInsecureMode) {
					t.Fatalf("Load at %04o: %v, want ErrInsecureMode", m, err)
				}
				if !strings.Contains(err.Error(), "chmod 600") {
					t.Errorf("error lacks a hint: %v", err)
				}
			} else if err != nil {
				t.Fatalf("Load at %04o: %v", m, err)
			}
			if err := os.Chmod(p.MetaFile, m); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadMeta(p); (m&0o077 != 0) != errors.Is(err, ErrInsecureMode) {
				t.Errorf("LoadMeta at %04o: %v", m, err)
			}
		})
	}
}

func TestLoadFailures(t *testing.T) {
	p := tempPaths(t)
	if _, err := Load(p); !errors.Is(err, ErrNoKey) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing key: %v", err)
	}
	if err := p.EnsureConfigDirs(); err != nil {
		t.Fatal(err)
	}
	// Wrong size.
	if err := os.WriteFile(p.KeyFile, make([]byte, 31), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("31-byte key: %v", err)
	}
	if err := os.WriteFile(p.KeyFile, make([]byte, 33), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("33-byte key: %v", err)
	}
	// A symlink to a 0600 file is refused.
	os.Remove(p.KeyFile)
	target := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("symlinked key: %v", err)
	}
	// A directory is refused.
	os.Remove(p.KeyFile)
	if err := os.Mkdir(p.KeyFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("directory key: %v", err)
	}
}

func TestKeyNeverPrintsSecret(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	k, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%s", k)} {
		if s != "keystore.Key{"+k.KeyID()+"}" {
			t.Errorf("formatted key = %q", s)
		}
	}
	if _, err := NewKeyFromSeed(seed[:31]); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("short seed: %v", err)
	}
}
