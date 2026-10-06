// Package raft is the CLI's only boundary to Raft. Every call goes through
// the Raft interface, whose production implementation runs the `raft` CLI as
// a subprocess. The CLI never speaks HTTP and never handles a token.
package raft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Timeout bounds every raft subprocess.
const Timeout = 30 * time.Second

// DefaultService is the service id used when neither --service nor
// CLAIM_CHECK_SERVICE is set.
const DefaultService = "claim-check"

// ServiceEnv is the environment variable that overrides the service id.
const ServiceEnv = "CLAIM_CHECK_SERVICE"

// Raft is everything the CLI asks of Raft.
type Raft interface {
	// Whoami returns the logged-in agent's server and agent IDs.
	Whoami() (serverID, agentID string, err error)
	// Invoke calls one app action with body as its JSON request body and
	// returns the app's HTTP status and response body (raw bytes).
	Invoke(action string, body []byte) (status int, result []byte, err error)
}

// Errors from the production implementation. Any error from Invoke means the
// outcome of the call is unknown to the CLI.
var (
	ErrNotInstalled   = errors.New("raft: the Raft CLI is not on PATH or has no 'integration' command")
	ErrNotLoggedIn    = errors.New("raft: not logged in")
	ErrTimeout        = errors.New("raft: timed out")
	ErrUnknownOutcome = errors.New("raft: unrecognised output, outcome unknown")
	ErrWhoami         = errors.New("raft: whoami failed")
)

// ResolveService applies the precedence flag, then CLAIM_CHECK_SERVICE, then
// DefaultService.
func ResolveService(flag string, lookup func(string) (string, bool)) string {
	if flag != "" {
		return flag
	}
	if v, ok := lookup(ServiceEnv); ok && v != "" {
		return v
	}
	return DefaultService
}

// WhoamiArgv is the argv (without the binary) of the identity call.
func WhoamiArgv() []string { return []string{"auth", "whoami"} }

// InvokeArgv is the argv (without the binary) of an action call. The body is
// never part of it: it goes on stdin.
func InvokeArgv(service, action string) []string {
	return []string{"integration", "invoke", service, action, "--data-file", "-", "--json"}
}

// CLI runs the real `raft` binary.
type CLI struct {
	Bin     string // "raft" in production
	Service string
	Timeout time.Duration
}

// New returns the production implementation for service.
func New(service string) *CLI { return &CLI{Bin: "raft", Service: service, Timeout: Timeout} }

var _ Raft = (*CLI)(nil)

// Whoami runs `raft auth whoami` and reads data.server.id and data.agent.id.
func (c *CLI) Whoami() (string, string, error) {
	stdout, stderr, err := c.exec(WhoamiArgv(), nil)
	var out struct {
		OK   bool `json:"ok"`
		Data struct {
			Agent  struct{ ID string } `json:"agent"`
			Server struct{ ID string } `json:"server"`
		} `json:"data"`
	}
	if jerr := json.Unmarshal(stdout, &out); jerr == nil && out.OK && out.Data.Agent.ID != "" && out.Data.Server.ID != "" {
		return out.Data.Server.ID, out.Data.Agent.ID, nil
	}
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrWhoami, classify(err, stdout, stderr))
	}
	return "", "", fmt.Errorf("%w: output has no data.server.id and data.agent.id%s", ErrWhoami, detail(stdout, stderr))
}

// Invoke runs `raft integration invoke <service> <action> --data-file - --json`
// with body on stdin. Output must be {"ok", "data": {"status", "result"}};
// anything else is ErrUnknownOutcome (or a more specific error).
func (c *CLI) Invoke(action string, body []byte) (int, []byte, error) {
	stdout, stderr, err := c.exec(InvokeArgv(c.Service, action), body)
	if errors.Is(err, ErrTimeout) || errors.Is(err, ErrNotInstalled) {
		return 0, nil, err
	}
	if status, result, ok := ParseInvokeOutput(stdout); ok {
		return status, result, nil
	}
	if err != nil {
		return 0, nil, classify(err, stdout, stderr)
	}
	return 0, nil, fmt.Errorf("%w%s", ErrUnknownOutcome, detail(stdout, stderr))
}

// ParseInvokeOutput reads the `raft integration invoke --json` output shape
// {"ok": bool, "data": {"service", "action", "status": int, "result": any}}.
// It reports ok=false for anything that does not have that shape.
func ParseInvokeOutput(stdout []byte) (status int, result []byte, ok bool) {
	var out struct {
		OK   *bool `json:"ok"`
		Data *struct {
			Status *json.Number    `json:"status"`
			Result json.RawMessage `json:"result"`
		} `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdout))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil || dec.More() {
		return 0, nil, false
	}
	if out.OK == nil || out.Data == nil || out.Data.Status == nil || out.Data.Result == nil {
		return 0, nil, false
	}
	n, err := out.Data.Status.Int64()
	if err != nil || n < 100 || n > 599 {
		return 0, nil, false
	}
	return int(n), []byte(out.Data.Result), true
}

func (c *CLI) exec(args []string, stdin []byte) (stdout, stderr []byte, err error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.WaitDelay = 2 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.Bytes(), errb.Bytes(), fmt.Errorf("%w after %s", ErrTimeout, timeout)
	}
	if cmd.Process == nil && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)) {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotInstalled, err)
	}
	return out.Bytes(), errb.Bytes(), err
}

var (
	unknownCommand = regexp.MustCompile(`(?i)unknown (sub)?command|no such command|unrecognized command`)
	notLoggedIn    = regexp.MustCompile(`(?i)not logged in|not authenticated|login required|unauthenticated`)
)

// classify maps a failed raft run to the submit-failure table's rows.
func classify(err error, stdout, stderr []byte) error {
	if errors.Is(err, ErrTimeout) || errors.Is(err, ErrNotInstalled) {
		return err
	}
	text := string(stderr) + "\n" + string(stdout)
	switch {
	case unknownCommand.MatchString(text):
		return fmt.Errorf("%w%s", ErrNotInstalled, detail(stdout, stderr))
	case notLoggedIn.MatchString(text):
		return fmt.Errorf("%w%s", ErrNotLoggedIn, detail(stdout, stderr))
	}
	return fmt.Errorf("%w: %v%s", ErrUnknownOutcome, err, detail(stdout, stderr))
}

// detail is a short, single-line excerpt of raft's own message.
func detail(stdout, stderr []byte) string {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		msg = strings.TrimSpace(string(stdout))
	}
	if msg == "" {
		return ""
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return " (" + msg + ")"
}
