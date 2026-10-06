// Package gitinfo reads the git fields of a receipt (payload.git) by running
// the `git` CLI. It only reads: it sets GIT_OPTIONAL_LOCKS=0 so that
// `git status` does not rewrite the index.
package gitinfo

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
	"github.com/jitokim/raft-claim-check/cli/internal/redact"
)

// Timeout bounds each git call.
const Timeout = 30 * time.Second

// Info is the repository that contains a directory.
type Info struct {
	Git  *receipt.Git // nil outside a repository (payload.git = null)
	Root string       // the repository's top level (symlinks resolved), "" outside
}

// Collect reads the repository containing dir. Outside a repository, or if
// git is not installed, it returns a zero Info.
func Collect(dir string) Info {
	root, ok := git(dir, "rev-parse", "--show-toplevel")
	if !ok || root == "" {
		return Info{}
	}
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	g := &receipt.Git{}
	if head, ok := git(dir, "rev-parse", "--verify", "-q", "HEAD^{commit}"); ok && head != "" {
		g.Head = &head
	}
	if branch, ok := git(dir, "symbolic-ref", "-q", "--short", "HEAD"); ok && branch != "" {
		g.Branch = &branch
	}
	if remote, ok := git(dir, "remote", "get-url", "origin"); ok && remote != "" {
		remote = StripUserinfo(remote)
		g.RemoteURL = &remote
	}
	status, ok := gitRaw(dir, "status", "--porcelain", "--untracked-files=normal")
	// If status cannot be read, the tree cannot be claimed clean.
	g.Dirty = !ok || len(bytes.TrimSpace(status)) > 0
	return Info{Git: g, Root: root}
}

// MaskHome returns i with home replaced by "~" in git.remote_url (see
// redact.MaskHome), which Collect has already passed through StripUserinfo.
// It covers a plain path and a file:// URL alike. Root is left unchanged,
// and i itself is not modified.
func (i Info) MaskHome(home string) Info {
	if i.Git == nil || i.Git.RemoteURL == nil {
		return i
	}
	g := *i.Git
	remote := redact.MaskHome(*g.RemoteURL, home)
	g.RemoteURL = &remote
	i.Git = &g
	return i
}

// RelDir returns dir relative to the repository root ("." at the root), or
// nil outside a repository or if dir is not under the root.
func (i Info) RelDir(dir string) *string {
	if i.Root == "" {
		return nil
	}
	rel, ok := Within(i.Root, dir)
	if !ok {
		return nil
	}
	return &rel
}

// Within resolves symlinks in path and reports its slash-separated path
// relative to root, and whether it lies inside root.
func Within(root, path string) (string, bool) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// StripUserinfo removes "user[:password]@" from a scheme:// URL. Other forms
// (such as scp-like git@host:path) are returned unchanged.
func StripUserinfo(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	authority := rest
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		authority = rest[:j]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return u
	}
	return u[:i+3] + rest[at+1:]
}

func git(dir string, args ...string) (string, bool) {
	out, ok := gitRaw(dir, args...)
	return strings.TrimSpace(string(out)), ok
}

func gitRaw(dir string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}
