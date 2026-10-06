package app

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/jitokim/raft-claim-check/cli/internal/gitinfo"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
	"github.com/jitokim/raft-claim-check/cli/internal/redact"
	"github.com/jitokim/raft-claim-check/cli/internal/spool"
)

// indexList collects repeated --redact-arg values.
type indexList []int

func (l *indexList) String() string { return fmt.Sprint([]int(*l)) }

func (l *indexList) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fmt.Errorf("want a non-negative integer, got %q", s)
	}
	*l = append(*l, n)
	return nil
}

// forwarded are the signals run passes on to the child.
var forwarded = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

func (a *app) cmdRun(args []string) int {
	fs, svc := a.newFlags("run")
	requireReceipt := fs.Bool("require-receipt", false, "exit 75 if the child exited 0 but the receipt was not stored")
	quiet := fs.Bool("quiet", false, "do not print the claim-check: line")
	var redactIdx indexList
	fs.Var(&redactIdx, "redact-arg", "mask the child's argv[N] (from 0) in full; repeatable")
	child, code, ok := a.parse(fs, args, true)
	if !ok {
		return code
	}
	if len(child) == 0 {
		return a.usageErr("run needs a command: claim-check run [flags] -- <cmd> [args...]")
	}
	for _, i := range redactIdx {
		if i >= len(child) {
			return a.usageErr("--redact-arg %d: the command has only %d argv elements (counting from 0)", i, len(child))
		}
	}

	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	key, meta, code := a.loadKey(p, true)
	if key == nil {
		return code
	}

	home := a.homeDir()
	red := redact.New(a.Environ()).WithHome(home)
	argv, argvRedactions := red.Argv(child, redactIdx)
	cwd, err := a.Getwd()
	if err != nil {
		a.logf("cannot read the working directory: %v", err)
		return ExitConfig
	}
	gi := gitinfo.Collect(cwd).MaskHome(home)
	header := receipt.Header{KeyID: key.KeyID(), BoundTo: *meta.BoundTo, CLI: a.cliInfo(), Git: gi.Git}
	rec := receipt.Run{Argv: argv, ArgvRedactions: int64(argvRedactions), CwdRel: gi.RelDir(cwd)}

	// Refuse before the child starts if the receipt could never be valid
	// (argv over the caps, for instance), so no run goes unrecorded.
	if err := probe(header, rec, a.Now()); err != nil {
		a.logf("cannot record this command: %v", err)
		return ExitUsage
	}

	cmd := exec.Command(child[0], child[1:]...)
	if cmd.Err != nil {
		return a.execFailed(child[0], cmd.Err)
	}
	cmd.Stdin = a.Stdin
	stdout, stderr := newCapture(a.Stdout), newCapture(a.Stderr)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	sigc := make(chan os.Signal, 8)
	signal.Notify(sigc, forwarded...)
	// Catch SIGPIPE so a write to a closed stdout or stderr returns EPIPE
	// instead of the Go runtime killing the CLI before the receipt is made.
	// It is caught, not ignored: an ignored disposition would survive exec
	// and change the child, while a caught one is reset to the default.
	// It stays caught until run returns, so the final line cannot kill it.
	pipec := make(chan os.Signal, 1)
	signal.Notify(pipec, syscall.SIGPIPE)
	defer func() {
		signal.Stop(pipec)
		close(pipec)
	}()
	go func() {
		for range pipec {
		}
	}()
	started, mono := a.Now(), time.Now()
	if err := cmd.Start(); err != nil {
		signal.Stop(sigc)
		return a.execFailed(child[0], err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for s := range sigc {
			if forwardSignal(s, childPgrp(cmd.Process.Pid), syscall.Getpgrp(), foregroundPgrp()) {
				_ = cmd.Process.Signal(s)
			}
		}
	}()
	_ = cmd.Wait() // a non-zero exit or a closed output is reported by ProcessState
	duration := time.Since(mono)
	finished := a.Now()
	signal.Stop(sigc)
	close(sigc)
	<-done

	exitCode, exit := exitStatus(cmd.ProcessState)
	rec.StartedAt = receipt.FormatTime(started)
	rec.FinishedAt = receipt.FormatTime(finished)
	rec.DurationMS = duration.Milliseconds()
	rec.Exit = exit
	rec.Stdout = stdout.stream(red)
	rec.Stderr = stderr.stream(red)

	res, id, err := a.signAndSubmit(p, key, func(h receipt.Header) (receipt.Payload, error) {
		return receipt.NewRunPayload(h, rec)
	}, header)
	stored := err == nil && res.outcome == outStored
	line := ""
	if err != nil {
		line = "no receipt: " + err.Error()
	} else {
		line = id + " " + res.summary
	}
	result := exitCode
	if *requireReceipt && !stored {
		if exitCode == 0 {
			result = ExitTempFail
			line += "; --require-receipt: the child exited 0 but the receipt was not stored, exiting 75"
		} else {
			line += fmt.Sprintf("; --require-receipt: passing through the child's exit code %d", exitCode)
		}
	}
	if !*quiet {
		a.logf("%s", line) // write errors ignored: stderr may be closed
	}
	return result
}

// forwardSignal reports whether run passes sig on to the child. A Ctrl-C
// at the terminal already sends SIGINT to every process in the foreground
// process group, so SIGINT is not forwarded when the child shares the CLI's
// group and that group is in the foreground. A group of -1 means unknown,
// and every other case forwards.
func forwardSignal(sig os.Signal, childPgrp, cliPgrp, foregroundPgrp int) bool {
	if sig != syscall.SIGINT || childPgrp < 0 || foregroundPgrp < 0 {
		return true
	}
	return !(childPgrp == cliPgrp && cliPgrp == foregroundPgrp)
}

// childPgrp returns the process group of pid, or -1 if it cannot be read.
func childPgrp(pid int) int {
	g, err := syscall.Getpgid(pid)
	if err != nil {
		return -1
	}
	return g
}

// foregroundPgrp returns the foreground process group of the controlling
// terminal, or -1 if there is none or it cannot be read.
func foregroundPgrp() int {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return -1
	}
	defer tty.Close()
	var pgrp int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), uintptr(syscall.TIOCGPGRP), uintptr(unsafe.Pointer(&pgrp))); errno != 0 {
		return -1
	}
	return int(pgrp)
}

// probe validates a provisional payload built from what is known before the
// child runs.
func probe(h receipt.Header, r receipt.Run, now time.Time) error {
	zero := int64(0)
	h.Nonce, h.SignedAt = "probe", now
	r.StartedAt, r.FinishedAt = receipt.FormatTime(now), receipt.FormatTime(now)
	r.Exit = receipt.Exit{Code: &zero}
	_, err := receipt.NewRunPayload(h, r)
	return err
}

// signAndSubmit completes the header, builds and signs the payload, writes
// it to the spool, and only then submits it.
func (a *app) signAndSubmit(p *profile, key crypto.Signer, build func(receipt.Header) (receipt.Payload, error), h receipt.Header) (submitResult, string, error) {
	nonce, err := receipt.NewNonce(a.Rand)
	if err != nil {
		return submitResult{}, "", err
	}
	h.Nonce, h.SignedAt = nonce, a.Now()
	payload, err := build(h)
	if err != nil {
		return submitResult{}, "", err
	}
	env, err := receipt.Sign(key, payload)
	if err != nil {
		return submitResult{}, "", err
	}
	entry, err := spool.Write(p.paths, env)
	if err != nil {
		return submitResult{}, "", fmt.Errorf("writing the spool: %w", err)
	}
	return a.submit(p, entry), entry.ID, nil
}

// execFailed reports a command that could not be started: 127 when it was
// not found, 126 when it exists but cannot be executed. No receipt is made.
func (a *app) execFailed(name string, err error) int {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrDot) {
		a.logf("%s: command not found (no receipt: nothing ran)", name)
		return ExitNotFound
	}
	a.logf("%s: cannot execute: %v (no receipt: nothing ran)", name, err)
	return ExitNoExec
}

// exitStatus returns the shell-style exit code and run.exit.
func exitStatus(ps *os.ProcessState) (int, receipt.Exit) {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		name := SignalName(ws.Signal())
		return 128 + int(ws.Signal()), receipt.Exit{Signal: &name}
	}
	code := int64(ps.ExitCode())
	return int(code), receipt.Exit{Code: &code}
}

var signalNames = map[syscall.Signal]string{
	syscall.SIGABRT: "SIGABRT", syscall.SIGALRM: "SIGALRM", syscall.SIGBUS: "SIGBUS",
	syscall.SIGCHLD: "SIGCHLD", syscall.SIGCONT: "SIGCONT", syscall.SIGFPE: "SIGFPE",
	syscall.SIGHUP: "SIGHUP", syscall.SIGILL: "SIGILL", syscall.SIGINT: "SIGINT",
	syscall.SIGIO: "SIGIO", syscall.SIGKILL: "SIGKILL", syscall.SIGPIPE: "SIGPIPE",
	syscall.SIGPROF: "SIGPROF", syscall.SIGQUIT: "SIGQUIT", syscall.SIGSEGV: "SIGSEGV",
	syscall.SIGSTOP: "SIGSTOP", syscall.SIGSYS: "SIGSYS", syscall.SIGTERM: "SIGTERM",
	syscall.SIGTRAP: "SIGTRAP", syscall.SIGTSTP: "SIGTSTP", syscall.SIGTTIN: "SIGTTIN",
	syscall.SIGTTOU: "SIGTTOU", syscall.SIGURG: "SIGURG", syscall.SIGUSR1: "SIGUSR1",
	syscall.SIGUSR2: "SIGUSR2", syscall.SIGVTALRM: "SIGVTALRM", syscall.SIGWINCH: "SIGWINCH",
	syscall.SIGXCPU: "SIGXCPU", syscall.SIGXFSZ: "SIGXFSZ",
}

// SignalName returns the conventional name ("SIGTERM"), or "SIG<n>".
func SignalName(s syscall.Signal) string {
	if n, ok := signalNames[s]; ok {
		return n
	}
	return "SIG" + strconv.Itoa(int(s))
}

// capture copies a child stream to out unchanged while hashing all of it and
// keeping its last redact.WindowBytes bytes. If out fails, the error goes
// back to os/exec, which closes the pipe, as a shell pipeline would.
type capture struct {
	out io.Writer
	h   hash.Hash
	n   int64
	buf []byte
}

func newCapture(out io.Writer) *capture {
	if out == nil {
		out = io.Discard
	}
	return &capture{out: out, h: sha256.New()}
}

func (c *capture) Write(p []byte) (int, error) {
	c.h.Write(p)
	c.n += int64(len(p))
	c.buf = append(c.buf, p...)
	if len(c.buf) > 2*redact.WindowBytes {
		c.buf = append(c.buf[:0], c.buf[len(c.buf)-redact.WindowBytes:]...)
	}
	return c.out.Write(p)
}

func (c *capture) window() []byte {
	if len(c.buf) > redact.WindowBytes {
		return c.buf[len(c.buf)-redact.WindowBytes:]
	}
	return c.buf
}

func (c *capture) stream(red *redact.Redactor) receipt.Stream {
	win := c.window()
	tail, truncated, n := red.Tail(win, c.n > int64(len(win)))
	var sum [sha256.Size]byte
	copy(sum[:], c.h.Sum(nil))
	return receipt.Stream{
		SHA256:         receipt.FormatHash(sum),
		Bytes:          c.n,
		Tail:           tail,
		TailTruncated:  truncated,
		TailRedactions: int64(n),
	}
}
