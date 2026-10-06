package gitinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestOutsideRepository(t *testing.T) {
	if i := Collect(t.TempDir()); i.Git != nil || i.Root != "" {
		t.Fatalf("got %+v", i)
	}
}

func TestRepositoryFields(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	dir := t.TempDir()
	gitT(t, dir, "init", "-q")
	// Before the first commit: head null, branch set.
	i := Collect(dir)
	if i.Git == nil || i.Git.Head != nil || i.Git.Branch == nil || *i.Git.Branch != "main" || i.Git.RemoteURL != nil {
		t.Fatalf("fresh repo: %+v", i.Git)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Collect(dir).Git.Dirty {
		t.Fatal("untracked file must make the tree dirty")
	}
	gitT(t, dir, "add", "a.txt")
	gitT(t, dir, "commit", "-q", "-m", "one")
	gitT(t, dir, "remote", "add", "origin", "https://user:pw@example.com/o/r.git")
	sub := filepath.Join(dir, "sub", "dir")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	i = Collect(sub)
	if i.Git.Head == nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*i.Git.Head) {
		t.Fatalf("head = %v", i.Git.Head)
	}
	if i.Git.Dirty {
		t.Fatal("clean tree reported dirty")
	}
	if *i.Git.RemoteURL != "https://example.com/o/r.git" {
		t.Fatalf("remote = %q", *i.Git.RemoteURL)
	}
	if rel := i.RelDir(sub); rel == nil || *rel != "sub/dir" {
		t.Fatalf("cwd_rel = %v", rel)
	}
	if rel := i.RelDir(dir); rel == nil || *rel != "." {
		t.Fatalf("cwd_rel at root = %v", rel)
	}
	gitT(t, dir, "checkout", "-q", "--detach")
	if b := Collect(dir).Git.Branch; b != nil {
		t.Fatalf("detached branch = %q", *b)
	}
}

func TestStripUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@host/x.git":     "https://host/x.git",
		"https://token@host/x":       "https://host/x",
		"ssh://git@host:22/x":        "ssh://host:22/x",
		"https://host/a@b":           "https://host/a@b",
		"git@github.com:o/r.git":     "git@github.com:o/r.git",
		"https://host/x?q=a@b#frag@": "https://host/x?q=a@b#frag@",
	} {
		if got := StripUserinfo(in); got != want {
			t.Errorf("StripUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInfoMaskHome(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	home := "/Users/alice"
	for remote, want := range map[string]string{
		"/Users/alice/x.git":                "~/x.git",
		"/Users/alice/x.git/":               "~/x.git/",
		"file:///Users/alice/x.git":         "file://~/x.git",
		"file://user:pw@/Users/alice/x.git": "file://~/x.git",
		"/Users/alicex/y.git":               "/Users/alicex/y.git",
		"git@github.com:o/r.git":            "git@github.com:o/r.git",
	} {
		dir := t.TempDir()
		gitT(t, dir, "init", "-q")
		gitT(t, dir, "remote", "add", "origin", remote)
		i := Collect(dir)
		before := *i.Git.RemoteURL
		m := i.MaskHome(home)
		if got := *m.Git.RemoteURL; got != want {
			t.Errorf("remote %q: remote_url = %q, want %q", remote, got, want)
		}
		if *i.Git.RemoteURL != before || m.Root != i.Root {
			t.Errorf("remote %q: MaskHome changed the original Info or Root", remote)
		}
		if got := *i.MaskHome("").Git.RemoteURL; got != before {
			t.Errorf("remote %q: empty home changed remote_url to %q", remote, got)
		}
	}
	if m := (Info{}).MaskHome(home); m.Git != nil {
		t.Fatalf("outside a repository: %+v", m)
	}
}
