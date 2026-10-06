// Package app is the claim-check command layer: argument parsing, the
// commands of the design's "### Commands" table, and exit codes. All Raft
// traffic goes through raft.Raft, so tests substitute a fake.
package app

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/raft"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// Exit codes. run passes the child's code through instead once it started.
const (
	ExitOK       = 0
	ExitFailure  = 1   // the command failed for good (refused, invalid input, bad signature)
	ExitUsage    = 64  // EX_USAGE
	ExitTempFail = 75  // EX_TEMPFAIL: not stored yet, retry later
	ExitConfig   = 78  // EX_CONFIG: no usable key, not registered, whoami failed
	ExitNoExec   = 126 // the command cannot be executed
	ExitNotFound = 127 // the command was not found
)

// Deps are the CLI's dependencies on the outside world.
type Deps struct {
	Stdin          io.Reader // inherited by run's child
	Stdout, Stderr io.Writer
	LookupEnv      func(string) (string, bool)
	Environ        func() []string // for env_value redaction only
	NewRaft        func(service string) raft.Raft
	Now            func() time.Time
	Rand           io.Reader
	Getwd          func() (string, error)
	Version        string
}

// DefaultDeps are the production dependencies.
func DefaultDeps(version string) Deps {
	return Deps{
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		LookupEnv: os.LookupEnv,
		Environ:   os.Environ,
		NewRaft:   func(s string) raft.Raft { return raft.New(s) },
		Now:       time.Now,
		Rand:      rand.Reader,
		Getwd:     os.Getwd,
		Version:   version,
	}
}

type app struct {
	Deps
	service string // from the global --service flag; a command flag overrides it
}

// Main runs claim-check with args (without the program name) and returns the
// process exit code.
func Main(args []string, d Deps) int {
	a := &app{Deps: d}
globals:
	for len(args) > 0 {
		arg := args[0]
		switch {
		case arg == "--service" || arg == "-service":
			if len(args) < 2 {
				return a.usageErr("--service needs a value")
			}
			a.service, args = args[1], args[2:]
		case strings.HasPrefix(arg, "--service=") || strings.HasPrefix(arg, "-service="):
			a.service, args = arg[strings.IndexByte(arg, '=')+1:], args[1:]
		case arg == "-h" || arg == "--help" || arg == "help":
			fmt.Fprint(a.Stdout, usage)
			return ExitOK
		case arg == "--version" || arg == "version":
			fmt.Fprintf(a.Stdout, "claim-check %s %s/%s\n", a.Version, runtime.GOOS, runtime.GOARCH)
			return ExitOK
		default:
			break globals
		}
	}
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return a.cmdRun(rest)
	case "attest":
		return a.cmdAttest(rest)
	case "flush":
		return a.cmdFlush(rest)
	case "verify":
		return a.cmdVerify(rest)
	case "key":
		if len(rest) == 0 {
			return a.usageErr("key needs a subcommand: init, register, show, list, revoke, rotate")
		}
		switch rest[0] {
		case "init":
			return a.cmdKeyInit(rest[1:])
		case "register":
			return a.cmdKeyRegister(rest[1:])
		case "show":
			return a.cmdKeyShow(rest[1:])
		case "list":
			return a.cmdKeyList(rest[1:])
		case "revoke":
			return a.cmdKeyRevoke(rest[1:])
		case "rotate":
			return a.cmdKeyRotate(rest[1:])
		}
		return a.usageErr("unknown key subcommand %q", rest[0])
	}
	return a.usageErr("unknown command %q", cmd)
}

const usage = `usage: claim-check [--service <id>] <command> [flags]

  run [--require-receipt] [--quiet] [--redact-arg N]... -- <cmd> [args...]
  attest --file <path>
  key init
  key register [--label <text>]
  key show
  key list
  key revoke [--key-id <id>] --reason rotated|lost|compromised [--compromised-since <time>]
  key rotate [--force]
  flush
  verify <receipt.json> [--public-key <ed25519:...>]

The service id is --service, else $CLAIM_CHECK_SERVICE, else claim-check.
`

// logf writes one "claim-check:" line to stderr.
func (a *app) logf(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "claim-check: "+format+"\n", args...)
}

func (a *app) usageErr(format string, args ...any) int {
	a.logf(format, args...)
	fmt.Fprint(a.Stderr, "run 'claim-check --help' for usage\n")
	return ExitUsage
}

// newFlags returns a flag set for one command with the shared --service flag.
func (a *app) newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("claim-check "+name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	svc := fs.String("service", "", "Raft service id (default $CLAIM_CHECK_SERVICE, else claim-check)")
	return fs, svc
}

// parse parses args with fs, allowing flags after positional arguments
// unless stop is set (run's child command must not be touched). It returns
// the positional arguments, or an exit code.
func (a *app) parse(fs *flag.FlagSet, args []string, stop bool) ([]string, int, bool) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, ExitOK, false
			}
			return nil, ExitUsage, false
		}
		args = fs.Args()
		if stop || len(args) == 0 {
			return append(pos, args...), 0, true
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), 0, true
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

// raftFor resolves the service id and returns the Raft boundary for it.
func (a *app) raftFor(flagService string) (raft.Raft, string, error) {
	if flagService == "" {
		flagService = a.service
	}
	svc := raft.ResolveService(flagService, a.LookupEnv)
	if strings.HasPrefix(svc, "-") || strings.ContainsAny(svc, " \t\n") {
		return nil, "", fmt.Errorf("invalid service id %q", svc)
	}
	return a.NewRaft(svc), svc, nil
}

// profile is the resolved per-(server, agent) location.
type profile struct {
	raft    raft.Raft
	service string
	paths   keystore.Paths
}

// openProfile runs whoami and resolves the key and spool directories. On
// failure it prints the error and a hint, and returns ExitConfig (or
// ExitUsage for a bad service id).
func (a *app) openProfile(flagService string) (*profile, int) {
	r, svc, err := a.raftFor(flagService)
	if err != nil {
		return nil, a.usageErr("%v", err)
	}
	serverID, agentID, err := r.Whoami()
	if err != nil {
		a.logf("cannot identify the Raft agent: %v", err)
		if errors.Is(err, raft.ErrNotInstalled) {
			a.logf("hint: this machine needs a Raft CLI with Agent Login")
		} else {
			a.logf("hint: run 'raft integration login --service %s'", svc)
		}
		return nil, ExitConfig
	}
	paths, err := keystore.Resolve(a.LookupEnv, serverID, agentID)
	if err != nil {
		a.logf("cannot locate the key directory: %v", err)
		return nil, ExitConfig
	}
	return &profile{raft: r, service: svc, paths: paths}, 0
}

// loadKey loads the private key and key.json and checks that they agree.
// requireBinding also requires a registered binding.
func (a *app) loadKey(p *profile, requireBinding bool) (*keystore.Key, keystore.Meta, int) {
	key, err := keystore.Load(p.paths)
	if err != nil {
		a.logf("no usable key: %v", err)
		if errors.Is(err, keystore.ErrNoKey) {
			a.logf("hint: run 'claim-check key init', then 'claim-check key register'")
		}
		return nil, keystore.Meta{}, ExitConfig
	}
	meta, err := keystore.LoadMeta(p.paths)
	if err != nil {
		a.logf("no usable key metadata: %v", err)
		return nil, keystore.Meta{}, ExitConfig
	}
	if meta.KeyID != key.KeyID() || meta.PublicKey != receipt.EncodePublicKey(key.PublicKey()) {
		a.logf("key.json does not describe the key file %s", p.paths.KeyFile)
		return nil, keystore.Meta{}, ExitConfig
	}
	if requireBinding && meta.BoundTo == nil {
		a.logf("key %s is not registered on this machine", key.KeyID())
		a.logf("hint: run 'claim-check key register'")
		return nil, keystore.Meta{}, ExitConfig
	}
	return key, meta, 0
}

func (a *app) cliInfo() receipt.CLI {
	return receipt.CLI{Name: receipt.CLIName, Version: a.Version, OS: runtime.GOOS, Arch: runtime.GOARCH}
}
