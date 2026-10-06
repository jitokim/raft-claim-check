package receipt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// Schema version strings, inside the signed payload.
const (
	SchemaReceipt      = "claim-check.receipt.v2"
	SchemaRegistration = "claim-check.key-registration.v2"
)

// Receipt kinds.
const (
	KindRun    = "run"
	KindAttest = "attest"
)

// CLIName is the fixed value of payload.cli.name.
const CLIName = "claim-check"

// Caps from the design that the CLI enforces before signing.
const (
	MaxArgv      = 128
	MaxArgvBytes = 8 * 1024
	MaxTailBytes = 2048
	MaxString    = 1024 // "Strings ≤ 1 KB unless stated otherwise"
)

// BoundTo is payload.bound_to: the (server, principal) the key is bound to.
type BoundTo struct {
	ServerID    string `json:"server_id"`
	PrincipalID string `json:"principal_id"`
}

// CLI is payload.cli.
type CLI struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Git is payload.git. A nil *Git encodes as null (outside a repository).
type Git struct {
	RemoteURL *string `json:"remote_url"`
	Head      *string `json:"head"`
	Branch    *string `json:"branch"`
	Dirty     bool    `json:"dirty"`
}

// Exit is run.exit. Exactly one of Code and Signal is non-nil.
type Exit struct {
	Code   *int64  `json:"code"`
	Signal *string `json:"signal"`
}

// Stream is run.stdout or run.stderr.
type Stream struct {
	SHA256         string `json:"sha256"`
	Bytes          int64  `json:"bytes"`
	Tail           string `json:"tail"`
	TailTruncated  bool   `json:"tail_truncated"`
	TailRedactions int64  `json:"tail_redactions"`
}

// Run is payload.run.
type Run struct {
	Argv           []string `json:"argv"`
	ArgvRedactions int64    `json:"argv_redactions"`
	CwdRel         *string  `json:"cwd_rel"`
	StartedAt      string   `json:"started_at"`
	FinishedAt     string   `json:"finished_at"`
	DurationMS     int64    `json:"duration_ms"`
	Exit           Exit     `json:"exit"`
	Stdout         Stream   `json:"stdout"`
	Stderr         Stream   `json:"stderr"`
}

// Attest is payload.attest.
type Attest struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	ObservedAt string `json:"observed_at"`
}

// Payload is the signed receipt payload. Exactly one of Run and Attest is
// set, matching Kind; the other is omitted from the JSON. Git is always
// present and may be null.
type Payload struct {
	Schema   string  `json:"schema"`
	Kind     string  `json:"kind"`
	Nonce    string  `json:"nonce"`
	KeyID    string  `json:"key_id"`
	BoundTo  BoundTo `json:"bound_to"`
	CLI      CLI     `json:"cli"`
	SignedAt string  `json:"signed_at"`
	Git      *Git    `json:"git"`
	Run      *Run    `json:"run,omitempty"`
	Attest   *Attest `json:"attest,omitempty"`
}

// Header holds the payload fields common to both receipt kinds.
type Header struct {
	Nonce    string    // from NewNonce
	KeyID    string    // the signing key's ID
	BoundTo  BoundTo   // from key.json, set at key register
	CLI      CLI       // Name is forced to CLIName
	SignedAt time.Time // formatted with FormatTime
	Git      *Git      // nil outside a repository
}

func (h Header) payload(kind string) Payload {
	cli := h.CLI
	cli.Name = CLIName
	return Payload{
		Schema:   SchemaReceipt,
		Kind:     kind,
		Nonce:    h.Nonce,
		KeyID:    h.KeyID,
		BoundTo:  h.BoundTo,
		CLI:      cli,
		SignedAt: FormatTime(h.SignedAt),
		Git:      h.Git,
	}
}

// NewRunPayload builds a run receipt payload and validates it.
func NewRunPayload(h Header, r Run) (Payload, error) {
	p := h.payload(KindRun)
	p.Run = &r
	return p, p.Validate()
}

// NewAttestPayload builds an attest receipt payload and validates it.
func NewAttestPayload(h Header, a Attest) (Payload, error) {
	p := h.payload(KindAttest)
	p.Attest = &a
	return p, p.Validate()
}

// ErrInvalidPayload is wrapped by Validate errors.
var ErrInvalidPayload = errors.New("receipt: invalid payload")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPayload, fmt.Sprintf(format, args...))
}

// Validate checks the structural rules the CLI can know before signing:
// schema and kind, kind/body consistency, the exit xor, the argv and tail
// caps, and time formats. The Worker re-checks everything.
func (p Payload) Validate() error {
	if p.Schema != SchemaReceipt {
		return invalid("schema %q", p.Schema)
	}
	if p.Nonce == "" || p.KeyID == "" || p.BoundTo.ServerID == "" || p.BoundTo.PrincipalID == "" {
		return invalid("nonce, key_id and bound_to are required")
	}
	if _, err := ParseTime(p.SignedAt); err != nil {
		return invalid("signed_at: %v", err)
	}
	strs := map[string]*string{"cli.version": &p.CLI.Version, "cli.os": &p.CLI.OS, "cli.arch": &p.CLI.Arch}
	if p.Git != nil {
		strs["git.remote_url"], strs["git.head"], strs["git.branch"] = p.Git.RemoteURL, p.Git.Head, p.Git.Branch
	}
	if p.Run != nil {
		strs["run.cwd_rel"] = p.Run.CwdRel
	}
	if p.Attest != nil {
		strs["attest.path"] = &p.Attest.Path
	}
	for name, v := range strs {
		if v != nil && len(*v) > MaxString {
			return invalid("%s is %d bytes, max %d", name, len(*v), MaxString)
		}
	}
	switch p.Kind {
	case KindRun:
		if p.Run == nil || p.Attest != nil {
			return invalid("kind run needs run and no attest")
		}
		return p.Run.validate()
	case KindAttest:
		if p.Attest == nil || p.Run != nil {
			return invalid("kind attest needs attest and no run")
		}
		return p.Attest.validate()
	default:
		return invalid("kind %q", p.Kind)
	}
}

func (r *Run) validate() error {
	if n := len(r.Argv); n < 1 || n > MaxArgv {
		return invalid("argv has %d elements, want 1..%d", n, MaxArgv)
	}
	total := 0
	for _, a := range r.Argv {
		total += len(a)
	}
	if total > MaxArgvBytes {
		return invalid("argv is %d bytes, max %d", total, MaxArgvBytes)
	}
	if (r.Exit.Code == nil) == (r.Exit.Signal == nil) {
		return invalid("exactly one of exit.code and exit.signal must be set")
	}
	for _, s := range []struct {
		name string
		v    Stream
	}{{"stdout", r.Stdout}, {"stderr", r.Stderr}} {
		if len(s.v.Tail) > MaxTailBytes {
			return invalid("%s.tail is %d bytes, max %d", s.name, len(s.v.Tail), MaxTailBytes)
		}
	}
	for _, t := range []string{r.StartedAt, r.FinishedAt} {
		if _, err := ParseTime(t); err != nil {
			return invalid("run time: %v", err)
		}
	}
	return nil
}

func (a *Attest) validate() error {
	if a.Path == "" {
		return invalid("attest.path is empty")
	}
	if _, err := ParseTime(a.ObservedAt); err != nil {
		return invalid("attest.observed_at: %v", err)
	}
	return nil
}

// Registration is the key-registration statement signed for register_key.
// Label is null when `key register` is given no --label.
type Registration struct {
	Schema      string  `json:"schema"`
	PublicKey   string  `json:"public_key"`
	KeyID       string  `json:"key_id"`
	ServerID    string  `json:"server_id"`
	PrincipalID string  `json:"principal_id"`
	IssuedAt    string  `json:"issued_at"`
	Nonce       string  `json:"nonce"`
	Label       *string `json:"label"`
	CLIVersion  string  `json:"cli_version"`
}

// NewRegistration builds the statement for pub, naming the session's server
// and principal. key_id is derived from pub, so the two always agree.
func NewRegistration(pub ed25519.PublicKey, serverID, principalID string, issuedAt time.Time, nonce string, label *string, cliVersion string) Registration {
	return Registration{
		Schema:      SchemaRegistration,
		PublicKey:   EncodePublicKey(pub),
		KeyID:       KeyID(pub),
		ServerID:    serverID,
		PrincipalID: principalID,
		IssuedAt:    FormatTime(issuedAt),
		Nonce:       nonce,
		Label:       label,
		CLIVersion:  cliVersion,
	}
}
