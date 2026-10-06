package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// vectorDir is spec/vectors at the repository root, relative to this
// package directory (cli/internal/vectors).
var vectorDir = filepath.Join("..", "..", "..", "spec", "vectors")

func readVector(t *testing.T, name string, into any) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("reading %s (run: go -C cli run ./cmd/genvectors): %v", name, err)
	}
	// The files must themselves pass the strict parser (no duplicate keys).
	if _, err := jcs.Parse(data); err != nil {
		t.Fatalf("%s is not strict JSON: %v", name, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return data
}

func TestFilesMatchGenerator(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(vectorDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; regenerate with: go -C cli run ./cmd/genvectors", name)
		}
	}
	again, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if !bytes.Equal(files[name], again[name]) {
			t.Errorf("Generate is not deterministic for %s", name)
		}
	}
}

func loadKey(t *testing.T) (KeyVector, ed25519.PrivateKey) {
	t.Helper()
	var kv KeyVector
	readVector(t, FileKey, &kv)
	seed, err := hex.DecodeString(kv.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("seed_hex: %v (len %d)", err, len(seed))
	}
	return kv, ed25519.NewKeyFromSeed(seed)
}

func TestKeyVector(t *testing.T) {
	kv, priv := loadKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	if got := receipt.EncodePublicKey(pub); got != kv.PublicKey {
		t.Errorf("public_key = %s, want %s", kv.PublicKey, got)
	}
	if got := receipt.KeyID(pub); got != kv.KeyID {
		t.Errorf("key_id = %s, want %s", kv.KeyID, got)
	}
	if len(kv.KeyID) != len("ck_")+26 {
		t.Errorf("key_id %q is not 26 base32 characters", kv.KeyID)
	}
	if kv.Comment == "" || !bytes.Contains([]byte(kv.Comment), []byte("TEST ONLY")) {
		t.Errorf("key.json comment must label the seed TEST ONLY")
	}
}

func TestSignedVectors(t *testing.T) {
	kv, priv := loadKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		file   string
		hasID  bool
		schema string
	}{
		{FileReceiptRun, true, receipt.SchemaReceipt},
		{FileReceiptAtt, true, receipt.SchemaReceipt},
		{FileRegistration, false, receipt.SchemaRegistration},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var raw struct {
				Payload   json.RawMessage `json:"payload"`
				JCS       *string         `json:"jcs"`
				SHA256    *string         `json:"sha256"`
				Envelope  json.RawMessage `json:"envelope"`
				ReceiptID *string         `json:"receipt_id"`
			}
			readVector(t, tc.file, &raw)
			if raw.JCS == nil || raw.SHA256 == nil || raw.Payload == nil || raw.Envelope == nil {
				t.Fatal("missing one of payload, jcs, sha256, envelope")
			}
			if tc.hasID != (raw.ReceiptID != nil) {
				t.Fatalf("receipt_id present = %v, want %v", raw.ReceiptID != nil, tc.hasID)
			}

			canonical, err := jcs.Canonicalize(raw.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != *raw.JCS {
				t.Errorf("jcs != JCS(payload)\n got %s\nwant %s", *raw.JCS, canonical)
			}
			sum := sha256.Sum256([]byte(*raw.JCS))
			if got := hex.EncodeToString(sum[:]); got != *raw.SHA256 {
				t.Errorf("sha256 = %s, want %s", *raw.SHA256, got)
			}
			if tc.hasID {
				if got := receipt.ReceiptID([]byte(*raw.JCS)); got != *raw.ReceiptID {
					t.Errorf("receipt_id = %s, want %s", *raw.ReceiptID, got)
				}
				if len(*raw.ReceiptID) != len("rcpt_")+26 {
					t.Errorf("receipt_id %q is not 26 base32 characters", *raw.ReceiptID)
				}
			}

			env, err := receipt.ParseEnvelope(raw.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(env.Payload, canonical) {
				t.Errorf("envelope.payload != payload")
			}
			if env.Signature.Alg != "ed25519" || env.Signature.KeyID != kv.KeyID {
				t.Errorf("signature alg/key_id = %q/%q", env.Signature.Alg, env.Signature.KeyID)
			}
			if err := receipt.Verify(env, pub); err != nil {
				t.Errorf("signature does not verify: %v", err)
			}
			want := receipt.EncodeSignature(ed25519.Sign(priv, canonical))
			if env.Signature.Value != want {
				t.Errorf("signature = %s, want deterministic %s", env.Signature.Value, want)
			}

			var fields map[string]any
			if err := json.Unmarshal(canonical, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["schema"] != tc.schema || fields["key_id"] != kv.KeyID {
				t.Errorf("schema/key_id = %v/%v", fields["schema"], fields["key_id"])
			}
			if tc.schema == receipt.SchemaRegistration {
				got, err := receipt.VerifyRegistration(env)
				if err != nil || !got.Equal(pub) {
					t.Errorf("VerifyRegistration: %v", err)
				}
			}
		})
	}
}

func TestJCSCasesVector(t *testing.T) {
	var cases []map[string]string
	readVector(t, FileJCSCases, &cases)
	if len(cases) < 10 {
		t.Fatalf("only %d cases, want at least 10", len(cases))
	}
	for i, c := range cases {
		in, okIn := c["input"]
		out, okOut := c["output"]
		if !okIn || !okOut || len(c) != 2 {
			t.Fatalf("case %d must be exactly {input, output}: %v", i, c)
		}
		got, err := jcs.Canonicalize([]byte(in))
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		if string(got) != out {
			t.Errorf("case %d:\n got %q\nwant %q", i, got, out)
		}
		// Canonical output is a fixed point.
		if again, err := jcs.Canonicalize([]byte(out)); err != nil || string(again) != out {
			t.Errorf("case %d output is not a fixed point: %q (%v)", i, again, err)
		}
	}
}
