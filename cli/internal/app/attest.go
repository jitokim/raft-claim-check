package app

import (
	"crypto/sha256"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jitokim/raft-claim-check/cli/internal/gitinfo"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

func (a *app) cmdAttest(args []string) int {
	fset, svc := a.newFlags("attest")
	file := fset.String("file", "", "the regular file to record")
	pos, code, ok := a.parse(fset, args, false)
	if !ok {
		return code
	}
	if len(pos) > 0 || *file == "" {
		return a.usageErr("usage: claim-check attest --file <path>")
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	key, meta, code := a.loadKey(p, true)
	if key == nil {
		return code
	}
	cwd, err := a.Getwd()
	if err != nil {
		a.logf("cannot read the working directory: %v", err)
		return ExitConfig
	}

	f, err := a.resolveAttestFile(cwd, *file)
	if err != nil {
		a.logf("attest %s: %v", *file, err)
		return ExitFailure
	}
	defer f.file.Close()
	h := sha256.New()
	n, err := io.Copy(h, f.file)
	if err != nil {
		a.logf("attest %s: reading: %v", *file, err)
		return ExitFailure
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	att := receipt.Attest{Path: f.recorded, SHA256: receipt.FormatHash(sum), Bytes: n, ObservedAt: receipt.FormatTime(a.Now())}

	header := receipt.Header{KeyID: key.KeyID(), BoundTo: *meta.BoundTo, CLI: a.cliInfo(), Git: f.git.Git}
	res, id, err := a.signAndSubmit(p, key, func(h receipt.Header) (receipt.Payload, error) {
		return receipt.NewAttestPayload(h, att)
	}, header)
	if err != nil {
		a.logf("no receipt: %v", err)
		return ExitFailure
	}
	a.logf("%s %s", id, res.summary)
	return exitFor[res.outcome]
}

// exitFor maps a submit outcome to the exit code of attest.
var exitFor = map[outcome]int{outStored: ExitOK, outKept: ExitTempFail, outRejected: ExitFailure}

type attestFile struct {
	file     *os.File
	recorded string // payload.attest.path
	git      gitinfo.Info
}

type attestError string

func (e attestError) Error() string { return string(e) }

// resolveAttestFile opens name for attest. It refuses directories, devices,
// pipes and sockets, and a symlink whose target is outside the repository
// (or, outside a repository, outside the working directory). The recorded
// path is the name as given, relative to the repository root, or its base
// name outside a repository.
func (a *app) resolveAttestFile(cwd, name string) (*attestFile, error) {
	abs := name
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	named := filepath.Join(dir, filepath.Base(abs))
	gi := gitinfo.Collect(dir)

	target := named
	if info.Mode()&fs.ModeSymlink != 0 {
		root, where := gi.Root, "the repository"
		if root == "" {
			if root, err = filepath.EvalSymlinks(cwd); err != nil {
				return nil, err
			}
			where = "the working directory"
		}
		if target, err = filepath.EvalSymlinks(named); err != nil {
			return nil, attestError("symlink target cannot be resolved: " + err.Error())
		}
		if _, inside := gitinfo.Within(root, target); !inside {
			return nil, attestError("refusing a symlink that points outside " + where)
		}
	}

	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	switch {
	case st.IsDir():
		f.Close()
		return nil, attestError("refusing a directory; attest records one regular file")
	case !st.Mode().IsRegular():
		f.Close()
		return nil, attestError("refusing a device, pipe or socket; attest records one regular file")
	}

	recorded := filepath.Base(named)
	if gi.Root != "" {
		if rel, err := filepath.Rel(gi.Root, named); err == nil && !strings.HasPrefix(rel, "..") {
			recorded = filepath.ToSlash(rel)
		}
	}
	return &attestFile{file: f, recorded: recorded, git: gi}, nil
}
