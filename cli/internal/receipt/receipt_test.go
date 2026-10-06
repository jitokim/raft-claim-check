package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func ptr[T any](v T) *T { return &v }

func header(priv ed25519.PrivateKey) Header {
	return Header{
		Nonce:    "AAAAAAAAAAAAAAAAAAAAAA",
		KeyID:    KeyID(priv.Public().(ed25519.PublicKey)),
		BoundTo:  BoundTo{ServerID: "srv_1", PrincipalID: "agent_1"},
		CLI:      CLI{Name: "ignored", Version: "2.0.0", OS: "linux", Arch: "amd64"},
		SignedAt: time.Date(2026, 10, 6, 9, 0, 3, 120_999_999, time.UTC),
	}
}

func runBody() Run {
	return Run{
		Argv:       []string{"true"},
		StartedAt:  "2026-10-06T09:00:00.000Z",
		FinishedAt: "2026-10-06T09:00:01.000Z",
		DurationMS: 1000,
		Exit:       Exit{Code: ptr(int64(0))},
		Stdout:     Stream{SHA256: HashBytes(nil)},
		Stderr:     Stream{SHA256: HashBytes(nil)},
	}
}

func TestIDDerivation(t *testing.T) {
	data := []byte(`{"a":1}`)
	sum := sha256.Sum256(data)
	want := "rcpt_" + strings.ToLower(base32.StdEncoding.EncodeToString(sum[:16])[:26])
	if got := ReceiptID(data); got != want || len(got) != 31 {
		t.Errorf("ReceiptID = %q, want %q", got, want)
	}
	pub := testKey(1).Public().(ed25519.PublicKey)
	ksum := sha256.Sum256(pub)
	kwant := "ck_" + strings.ToLower(base32.StdEncoding.EncodeToString(ksum[:16])[:26])
	if got := KeyID(pub); got != kwant || len(got) != 29 {
		t.Errorf("KeyID = %q, want %q", got, kwant)
	}
	if KeyID(testKey(2).Public().(ed25519.PublicKey)) == kwant {
		t.Error("different keys gave the same key_id")
	}
	if strings.ContainsAny(ReceiptID(data), "=ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Error("receipt_id must be lowercase and unpadded")
	}
}

func TestEncodings(t *testing.T) {
	pub := testKey(1).Public().(ed25519.PublicKey)
	enc := EncodePublicKey(pub)
	if !strings.HasPrefix(enc, "ed25519:") || strings.Contains(enc, "=") || len(enc) != 8+43 {
		t.Errorf("EncodePublicKey = %q", enc)
	}
	back, err := ParsePublicKey(enc)
	if err != nil || !back.Equal(pub) {
		t.Errorf("ParsePublicKey round trip: %v", err)
	}
	for _, bad := range []string{
		enc + "=", // padding
		strings.TrimPrefix(enc, "ed25519:"),
		"ed25519:" + enc[8:len(enc)-1] + "B", // non-zero trailing bits
		"ed25519:AAAA",                       // wrong length
		"ed25519:/" + enc[9:],                // standard, not URL, alphabet
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%q) succeeded", bad)
		}
	}
	if got := HashBytes([]byte("abc")); got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("HashBytes = %s", got)
	}
	n, err := NewNonce(bytes.NewReader(make([]byte, 16)))
	if err != nil || n != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("NewNonce = %q, %v", n, err)
	}
	if _, err := NewNonce(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Error("NewNonce with a short reader succeeded")
	}
}

func TestTimes(t *testing.T) {
	loc := time.FixedZone("KST", 9*3600)
	got := FormatTime(time.Date(2026, 10, 6, 10, 2, 3, 456_789_000, loc))
	if got != "2026-10-06T01:02:03.456Z" {
		t.Errorf("FormatTime = %s", got)
	}
	if got := FormatTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != "2026-01-02T03:04:05.000Z" {
		t.Errorf("FormatTime = %s", got)
	}
	if _, err := ParseTime("2026-10-06T01:02:03.456Z"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"2026-10-06T01:02:03Z", "2026-10-06T01:02:03.45Z", "2026-10-06T01:02:03.4567Z",
		"2026-10-06T10:02:03.456+09:00", "2026-10-06t01:02:03.456z", "2026-10-06 01:02:03.456Z"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("ParseTime(%q) succeeded", bad)
		}
	}
}

func TestRunPayloadShape(t *testing.T) {
	priv := testKey(1)
	p, err := NewRunPayload(header(priv), runBody())
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "kind", "nonce", "key_id", "bound_to", "cli", "signed_at", "git", "run"} {
		if _, ok := m[k]; !ok {
			t.Errorf("payload missing %q", k)
		}
	}
	if _, ok := m["attest"]; ok {
		t.Error("run payload must not contain attest")
	}
	if m["git"] != nil || m["signed_at"] != "2026-10-06T09:00:03.120Z" || m["schema"] != SchemaReceipt {
		t.Errorf("git/signed_at/schema = %v/%v/%v", m["git"], m["signed_at"], m["schema"])
	}
	if m["cli"].(map[string]any)["name"] != "claim-check" {
		t.Error("cli.name must be claim-check")
	}
	exit := m["run"].(map[string]any)["exit"].(map[string]any)
	if v, ok := exit["signal"]; !ok || v != nil {
		t.Error("exit.signal must be present and null")
	}
}

func TestAttestPayloadShape(t *testing.T) {
	priv := testKey(1)
	h := header(priv)
	h.Git = &Git{Dirty: true}
	p, err := NewAttestPayload(h, Attest{Path: "a.txt", SHA256: HashBytes(nil), ObservedAt: "2026-10-06T09:00:00.000Z"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `"run"`) || !strings.Contains(s, `"git":{"remote_url":null,"head":null,"branch":null,"dirty":true}`) {
		t.Errorf("attest payload = %s", s)
	}
}

func TestValidateFailures(t *testing.T) {
	h := header(testKey(1))
	for name, mut := range map[string]func(*Run){
		"no argv":       func(r *Run) { r.Argv = nil },
		"argv too long": func(r *Run) { r.Argv = make([]string, MaxArgv+1) },
		"argv too big":  func(r *Run) { r.Argv = []string{strings.Repeat("x", MaxArgvBytes+1)} },
		"both exit":     func(r *Run) { r.Exit.Signal = ptr("SIGKILL") },
		"no exit":       func(r *Run) { r.Exit.Code = nil },
		"tail too big":  func(r *Run) { r.Stdout.Tail = strings.Repeat("x", MaxTailBytes+1) },
		"bad time":      func(r *Run) { r.StartedAt = "yesterday" },
	} {
		r := runBody()
		mut(&r)
		if _, err := NewRunPayload(h, r); !errors.Is(err, ErrInvalidPayload) {
			t.Errorf("%s: error = %v, want ErrInvalidPayload", name, err)
		}
	}
	if _, err := NewAttestPayload(h, Attest{ObservedAt: "2026-10-06T09:00:00.000Z"}); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("empty attest path: %v", err)
	}
	p, _ := NewRunPayload(h, runBody())
	p.Attest = &Attest{}
	if err := p.Validate(); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("run with attest: %v", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	p, _ := NewRunPayload(header(priv), runBody())
	env, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Through JSON (as spooled) and back.
	data, err := json.Marshal(map[string]any{"receipt": env})
	if err != nil {
		t.Fatal(err)
	}
	back, id, err := FindEnvelope(data)
	if err != nil || id != "" {
		t.Fatalf("FindEnvelope: %v %q", err, id)
	}
	if err := Verify(back, pub); err != nil || back.ReceiptID() != env.ReceiptID() {
		t.Fatalf("Verify after JSON round trip: %v", err)
	}
	// A pretty-printed, re-ordered copy still verifies: JCS is recomputed.
	var generic any
	_ = json.Unmarshal(data, &generic)
	pretty, _ := json.MarshalIndent(generic, "", "    ")
	back2, _, err := FindEnvelope(pretty)
	if err != nil || Verify(back2, pub) != nil {
		t.Fatalf("pretty copy does not verify: %v", err)
	}
	// Stored-receipt shape.
	stored, _ := json.Marshal(map[string]any{"receipt_id": env.ReceiptID(), "envelope": env, "ledger": map[string]any{}})
	back3, id, err := FindEnvelope(stored)
	if err != nil || id != env.ReceiptID() || Verify(back3, pub) != nil {
		t.Fatalf("stored shape: %v %q", err, id)
	}
}

func TestRegistrationRoundTrip(t *testing.T) {
	priv := testKey(3)
	pub := priv.Public().(ed25519.PublicKey)
	stmt := NewRegistration(pub, "srv_1", "agent_1", time.Date(2026, 10, 6, 8, 59, 0, 0, time.UTC), "AAAAAAAAAAAAAAAAAAAAAA", nil, "2.0.0")
	env, err := Sign(priv, stmt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env.Payload), `"label":null`) {
		t.Errorf("label must be null when unset: %s", env.Payload)
	}
	got, err := VerifyRegistration(env)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	// Someone else's public key in the statement, signed with my key.
	other := testKey(4).Public().(ed25519.PublicKey)
	forged := NewRegistration(other, "srv_1", "agent_1", time.Now(), "AAAAAAAAAAAAAAAAAAAAAA", nil, "2.0.0")
	if _, err := Sign(priv, forged); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("Sign with foreign key_id: %v", err)
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	p, _ := NewRunPayload(header(priv), runBody())
	env, _ := Sign(priv, p)
	tampered := env
	tampered.Payload = bytes.Replace(env.Payload, []byte(`"code":0`), []byte(`"code":1`), 1)
	if bytes.Equal(tampered.Payload, env.Payload) {
		t.Fatal("tamper did not change the payload")
	}
	if err := Verify(tampered, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered payload: %v, want ErrBadSignature", err)
	}
	// Flipped signature byte.
	sig, _ := ParseSignature(env.Signature.Value)
	sig[0] ^= 1
	bad := env
	bad.Signature.Value = EncodeSignature(sig)
	if err := Verify(bad, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("flipped signature: %v", err)
	}
	// Padded signature encoding is non-canonical.
	bad.Signature.Value = env.Signature.Value + "=="
	if err := Verify(bad, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("padded signature: %v", err)
	}
	bad = env
	bad.Signature.Alg = "EdDSA"
	if err := Verify(bad, pub); !errors.Is(err, ErrMalformed) {
		t.Errorf("wrong alg: %v", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	priv := testKey(1)
	p, _ := NewRunPayload(header(priv), runBody())
	env, _ := Sign(priv, p)
	other := testKey(2).Public().(ed25519.PublicKey)
	if err := Verify(env, other); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("wrong key: %v, want ErrKeyMismatch", err)
	}
	// Even with key_ids rewritten to the other key, the signature fails.
	forged := env
	forged.Signature.KeyID = KeyID(other)
	forged.Payload = bytes.Replace(env.Payload, []byte(KeyID(priv.Public().(ed25519.PublicKey))), []byte(KeyID(other)), 1)
	if err := Verify(forged, other); !errors.Is(err, ErrBadSignature) {
		t.Errorf("rewritten key_id: %v, want ErrBadSignature", err)
	}
	// Signing a payload whose key_id is not the signer's is refused.
	if _, err := Sign(testKey(2), p); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("Sign with mismatched key: %v", err)
	}
}

func TestParseEnvelopeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not object":       `[]`,
		"no payload":       `{"signature":{"alg":"ed25519","key_id":"k","value":"v"}}`,
		"payload array":    `{"payload":[],"signature":{"alg":"ed25519","key_id":"k","value":"v"}}`,
		"no signature":     `{"payload":{}}`,
		"sig value number": `{"payload":{},"signature":{"alg":"ed25519","key_id":"k","value":1}}`,
		"duplicate key":    `{"payload":{"a":1,"a":2},"signature":{"alg":"ed25519","key_id":"k","value":"v"}}`,
		"float":            `{"payload":{"a":1.5},"signature":{"alg":"ed25519","key_id":"k","value":"v"}}`,
	} {
		if _, err := ParseEnvelope([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}
