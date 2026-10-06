// Command genvectors writes the shared test vectors to spec/vectors/ at the
// repository root:
//
//	go -C cli run ./cmd/genvectors
//
// The output is deterministic. By default the repository root is found by
// walking up from the working directory to cli/go.mod; -out overrides the
// destination directory.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jitokim/raft-claim-check/cli/internal/vectors"
)

func main() {
	out := flag.String("out", "", "destination directory (default: <repo>/spec/vectors)")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	if out == "" {
		cliDir, err := findModuleDir()
		if err != nil {
			return err
		}
		out = filepath.Join(filepath.Dir(cliDir), "spec", "vectors")
	}
	files, err := vectors.Generate()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", path)
	}
	return nil
}

// findModuleDir walks up from the working directory to the directory holding
// the cli module's go.mod.
func findModuleDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && filepath.Base(dir) == "cli" {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("cannot find cli/go.mod above the working directory; use -out")
		}
		dir = parent
	}
}
