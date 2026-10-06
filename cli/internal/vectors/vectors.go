// Package vectors builds the shared test vectors in spec/vectors/ that the
// CLI and the Worker both test against. Everything is fixed: a TEST ONLY
// seed, fixed nonces, fixed times, fixed values. Generate always returns the
// same bytes.
package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// TestSeed is the fixed Ed25519 seed for the vectors. TEST ONLY: it is
// public, so anything signed with it proves nothing.
var TestSeed = []byte("claim-check-v2 TEST ONLY seed!!!")

// TestSeedComment labels the seed inside key.json.
const TestSeedComment = "TEST ONLY. seed_hex is a fixed, public test seed (the ASCII text " +
	"\"claim-check-v2 TEST ONLY seed!!!\"). Never use it as a real key."

// File names under spec/vectors/.
const (
	FileKey          = "key.json"
	FileReceiptRun   = "receipt-run.json"
	FileReceiptAtt   = "receipt-attest.json"
	FileRegistration = "registration.json"
	FileJCSCases     = "jcs-cases.json"
)

// KeyVector is key.json.
type KeyVector struct {
	Comment   string `json:"comment"`
	SeedHex   string `json:"seed_hex"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
}

// SignedVector is receipt-*.json and registration.json. ReceiptID is
// omitted for registration.json.
type SignedVector struct {
	Payload   json.RawMessage  `json:"payload"`
	JCS       string           `json:"jcs"`
	SHA256    string           `json:"sha256"`
	Envelope  receipt.Envelope `json:"envelope"`
	ReceiptID string           `json:"receipt_id,omitempty"`
}

// JCSCase is one entry of jcs-cases.json.
type JCSCase struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func ptr[T any](v T) *T { return &v }

// fixedNonce gives a deterministic 16-byte nonce for vector n.
func fixedNonce(n byte) string {
	b := bytes.Repeat([]byte{n}, receipt.NonceSize)
	nonce, err := receipt.NewNonce(bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	return nonce
}

func testHeader(key *keystore.Key, nonce byte, signedAt string, git *receipt.Git) receipt.Header {
	return receipt.Header{
		Nonce:    fixedNonce(nonce),
		KeyID:    key.KeyID(),
		BoundTo:  receipt.BoundTo{ServerID: "srv_test", PrincipalID: "agent_test"},
		CLI:      receipt.CLI{Version: "2.0.0-test", OS: "linux", Arch: "amd64"},
		SignedAt: at(signedAt),
		Git:      git,
	}
}

// RunPayload is the fixed run receipt payload.
func RunPayload(key *keystore.Key) (receipt.Payload, error) {
	stdout := "ok  \texample.com/widgets/api\t1.204s\nok  \texample.com/widgets/ünïcode\t0.811s\n"
	stderr := "warning: \"quoted\" \\ backslash, tab\there, <html> & 😀\n"
	git := &receipt.Git{
		RemoteURL: ptr("https://github.com/example/widgets.git"),
		Head:      ptr("0123456789abcdef0123456789abcdef01234567"),
		Branch:    ptr("main"),
		Dirty:     false,
	}
	return receipt.NewRunPayload(testHeader(key, 0x01, "2026-10-06T09:00:03.120Z", git), receipt.Run{
		Argv:           []string{"go", "test", "./...", "-token=[REDACTED:sensitive_flag]"},
		ArgvRedactions: 1,
		CwdRel:         ptr("."),
		StartedAt:      receipt.FormatTime(at("2026-10-06T09:00:00.020Z")),
		FinishedAt:     receipt.FormatTime(at("2026-10-06T09:00:03.050Z")),
		DurationMS:     3030,
		Exit:           receipt.Exit{Code: ptr(int64(0))},
		Stdout: receipt.Stream{
			SHA256: receipt.HashBytes([]byte(stdout)), Bytes: int64(len(stdout)),
			Tail: stdout, TailTruncated: false, TailRedactions: 0,
		},
		Stderr: receipt.Stream{
			SHA256: receipt.HashBytes([]byte(stderr)), Bytes: int64(len(stderr)),
			Tail: stderr, TailTruncated: false, TailRedactions: 0,
		},
	})
}

// AttestPayload is the fixed attest receipt payload. It uses a repository
// before its first commit, so git.head and git.remote_url are null.
func AttestPayload(key *keystore.Key) (receipt.Payload, error) {
	contents := []byte("claim-check attest vector file contents\n")
	git := &receipt.Git{Branch: ptr("main"), Dirty: true}
	return receipt.NewAttestPayload(testHeader(key, 0x02, "2026-10-06T09:10:00.500Z", git), receipt.Attest{
		Path:       "dist/widgets-1.0.0.tar.gz",
		SHA256:     receipt.HashBytes(contents),
		Bytes:      int64(len(contents)),
		ObservedAt: receipt.FormatTime(at("2026-10-06T09:09:59.999Z")),
	})
}

// RegistrationPayload is the fixed key-registration statement.
func RegistrationPayload(key *keystore.Key) receipt.Registration {
	return receipt.NewRegistration(key.PublicKey(), "srv_test", "agent_test",
		at("2026-10-06T08:59:00.000Z"), fixedNonce(0x03), ptr("laptop-test"), "2.0.0-test")
}

// JCSCases are the canonicalization cases: input JSON text and its JCS.
var JCSCases = []JCSCase{
	// Key ordering, ASCII.
	{`{"b":2,"a":1,"c":3}`, `{"a":1,"b":2,"c":3}`},
	// Key ordering with non-ASCII keys.
	{`{"日本":4,"é":1,"z":3,"e":2,"A":5}`, `{"A":5,"e":2,"z":3,"é":1,"日本":4}`},
	// UTF-16 order differs from code-point and byte order: U+10000 (surrogates
	// D800 DC00) sorts before U+FFFD.
	{`{"\ufffd":1,"\ud800\udc00":2}`, "{\"\U00010000\":2,\"\ufffd\":1}"},
	// RFC 8785 section 3.2.3 sorting example.
	{
		`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
		"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
	},
	// The two-character escapes; "\/" is written as a plain "/".
	{`"\u0008\u000c\u000a\u000d\u0009\u0022\u005c\/"`, `"\b\f\n\r\t\"\\/"`},
	// Other control characters use lowercase \u00XX; DEL (U+007F) is literal.
	{`"\u0000\u0001\u001F\u001b\u007f"`, "\"\\u0000\\u0001\\u001f\\u001b\x7f\""},
	// Non-ASCII, U+2028 and HTML-significant characters are literal UTF-8.
	{`"\u00e9\u65E5\ud83d\ude00\u2028<>&'"`, "\"é日😀\u2028<>&'\""},
	// Escapes inside keys, sorted by the unescaped key.
	{`{"a\"b":2,"a\nb":1}`, `{"a\nb":1,"a\"b":2}`},
	// Nested arrays and objects; array order is kept.
	{
		`{"z":[3,{"y":true,"x":null}],"a":{"c":[[],[1,[2]]],"b":{"k":{"j":"v"}}}}`,
		`{"a":{"b":{"k":{"j":"v"}},"c":[[],[1,[2]]]},"z":[3,{"x":null,"y":true}]}`,
	},
	// Empty containers.
	{`[ {}, [], "", {"":[]} ]`, `[{},[],"",{"":[]}]`},
	// Integer bounds ±2^53; -0 becomes 0.
	{`[9007199254740992,-9007199254740992,0,-0,1,-1]`, `[9007199254740992,-9007199254740992,0,0,1,-1]`},
	// Whitespace between tokens is dropped; literals.
	{" \t\r\n{ \"a\" : [ true , false , null ] }\n", `{"a":[true,false,null]}`},
	// Top-level scalars.
	{`"top"`, `"top"`},
	{`123`, `123`},
}

// Generate returns every vector file, keyed by file name, as pretty-printed
// JSON ending in a newline.
func Generate() (map[string][]byte, error) {
	key, err := keystore.NewKeyFromSeed(TestSeed)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	add := func(name string, v any) error {
		b, err := pretty(v)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		out[name] = b
		return nil
	}

	if err := add(FileKey, KeyVector{
		Comment:   TestSeedComment,
		SeedHex:   hex.EncodeToString(TestSeed),
		PublicKey: receipt.EncodePublicKey(key.PublicKey()),
		KeyID:     key.KeyID(),
	}); err != nil {
		return nil, err
	}

	run, err := RunPayload(key)
	if err != nil {
		return nil, err
	}
	attest, err := AttestPayload(key)
	if err != nil {
		return nil, err
	}
	for _, s := range []struct {
		name      string
		payload   any
		receiptID bool
	}{
		{FileReceiptRun, run, true},
		{FileReceiptAtt, attest, true},
		{FileRegistration, RegistrationPayload(key), false},
	} {
		v, err := signed(key, s.payload, s.receiptID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		if err := add(s.name, v); err != nil {
			return nil, err
		}
	}

	for i, c := range JCSCases {
		got, err := jcs.Canonicalize([]byte(c.Input))
		if err != nil || string(got) != c.Output {
			return nil, fmt.Errorf("jcs case %d: got %q (%v), want %q", i, got, err, c.Output)
		}
	}
	if err := add(FileJCSCases, JCSCases); err != nil {
		return nil, err
	}
	return out, nil
}

func signed(key *keystore.Key, payload any, withID bool) (SignedVector, error) {
	env, err := receipt.Sign(key, payload)
	if err != nil {
		return SignedVector{}, err
	}
	v := SignedVector{
		Payload:  env.Payload,
		JCS:      string(env.Payload),
		SHA256:   receipt.HashBytes(env.Payload)[len(receipt.HashPrefix):],
		Envelope: env,
	}
	if withID {
		v.ReceiptID = env.ReceiptID()
	}
	return v, nil
}

func pretty(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
