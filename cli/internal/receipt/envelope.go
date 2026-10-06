package receipt

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
)

// AlgEd25519 is the only signature algorithm.
const AlgEd25519 = "ed25519"

// Signature is the detached envelope signature.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// Envelope is {"payload": ..., "signature": {...}}. Payload always holds the
// JCS bytes of the signed payload, both after Sign and after ParseEnvelope.
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}

// Errors returned by Sign, ParseEnvelope and the Verify functions.
var (
	ErrMalformed    = errors.New("receipt: malformed envelope")
	ErrKeyMismatch  = errors.New("receipt: key_id does not match")
	ErrBadSignature = errors.New("receipt: signature does not verify")
)

// Sign canonicalizes payload (a Payload, a Registration, or any JSON-able
// value with a "key_id" field), signs the JCS bytes with signer, and returns
// the envelope. It refuses a payload whose key_id is not the signer's.
func Sign(signer crypto.Signer, payload any) (Envelope, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return Envelope{}, fmt.Errorf("receipt: signer is not ed25519")
	}
	canonical, err := jcs.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("receipt: canonicalizing payload: %w", err)
	}
	keyID := KeyID(pub)
	if got, err := payloadKeyID(canonical); err != nil {
		return Envelope{}, err
	} else if got != keyID {
		return Envelope{}, fmt.Errorf("%w: payload key_id %q, signer %q", ErrKeyMismatch, got, keyID)
	}
	sig, err := signer.Sign(nil, canonical, crypto.Hash(0))
	if err != nil {
		return Envelope{}, fmt.Errorf("receipt: signing: %w", err)
	}
	return Envelope{
		Payload:   canonical,
		Signature: Signature{Alg: AlgEd25519, KeyID: keyID, Value: EncodeSignature(sig)},
	}, nil
}

// ReceiptID returns the ID derived from the envelope's payload.
func (e Envelope) ReceiptID() string { return ReceiptID(e.Payload) }

// MarshalJSON writes the envelope as JCS, so a spooled or printed envelope
// carries the signed bytes verbatim.
func (e Envelope) MarshalJSON() ([]byte, error) {
	payload, err := jcs.Parse(e.Payload)
	if err != nil {
		return nil, err
	}
	return jcs.Encode(map[string]any{
		"payload": payload,
		"signature": map[string]any{
			"alg":    e.Signature.Alg,
			"key_id": e.Signature.KeyID,
			"value":  e.Signature.Value,
		},
	})
}

// ParseEnvelope strictly parses a bare envelope object.
func ParseEnvelope(data []byte) (Envelope, error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return envelopeFromValue(v)
}

// FindEnvelope strictly parses a document that holds an envelope in any of
// the shapes the CLI meets: a bare envelope, a request body
// {"receipt": env} or {"registration": env}, or a stored receipt
// {"receipt_id", "envelope", "ledger", ...}. For a stored receipt it also
// returns the claimed receipt_id (empty otherwise), which the caller should
// compare with Envelope.ReceiptID.
func FindEnvelope(data []byte) (env Envelope, claimedID string, err error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return Envelope{}, "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return Envelope{}, "", fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	if inner, ok := obj["envelope"]; ok {
		if id, ok := obj["receipt_id"].(string); ok {
			claimedID = id
		}
		env, err = envelopeFromValue(inner)
		return env, claimedID, err
	}
	for _, k := range []string{"receipt", "registration"} {
		if inner, ok := obj[k]; ok {
			env, err = envelopeFromValue(inner)
			return env, "", err
		}
	}
	env, err = envelopeFromValue(v)
	return env, "", err
}

func envelopeFromValue(v any) (Envelope, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return Envelope{}, fmt.Errorf("%w: envelope is not an object", ErrMalformed)
	}
	payload, ok := obj["payload"].(map[string]any)
	if !ok {
		return Envelope{}, fmt.Errorf("%w: payload missing or not an object", ErrMalformed)
	}
	sigObj, ok := obj["signature"].(map[string]any)
	if !ok {
		return Envelope{}, fmt.Errorf("%w: signature missing or not an object", ErrMalformed)
	}
	var sig Signature
	for name, dst := range map[string]*string{"alg": &sig.Alg, "key_id": &sig.KeyID, "value": &sig.Value} {
		s, ok := sigObj[name].(string)
		if !ok {
			return Envelope{}, fmt.Errorf("%w: signature.%s missing or not a string", ErrMalformed, name)
		}
		*dst = s
	}
	canonical, err := jcs.Encode(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return Envelope{Payload: canonical, Signature: sig}, nil
}

// Verify checks the envelope against pub: alg is ed25519, signature.key_id
// and payload.key_id both equal KeyID(pub), and the signature verifies over
// JCS(payload). It works for receipts and registration statements alike.
func Verify(e Envelope, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes", ErrEncoding, len(pub))
	}
	if e.Signature.Alg != AlgEd25519 {
		return fmt.Errorf("%w: signature.alg %q", ErrMalformed, e.Signature.Alg)
	}
	canonical, err := jcs.Canonicalize(e.Payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	want := KeyID(pub)
	if e.Signature.KeyID != want {
		return fmt.Errorf("%w: signature.key_id %q, public key gives %q", ErrKeyMismatch, e.Signature.KeyID, want)
	}
	if got, err := payloadKeyID(canonical); err != nil {
		return err
	} else if got != want {
		return fmt.Errorf("%w: payload.key_id %q, public key gives %q", ErrKeyMismatch, got, want)
	}
	sig, err := ParseSignature(e.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyRegistration checks a key-registration envelope against the public
// key named inside its own statement, as register_key does. It returns that
// public key on success.
func VerifyRegistration(e Envelope) (ed25519.PublicKey, error) {
	var stmt Registration
	if err := json.Unmarshal(e.Payload, &stmt); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if stmt.Schema != SchemaRegistration {
		return nil, fmt.Errorf("%w: schema %q is not %q", ErrMalformed, stmt.Schema, SchemaRegistration)
	}
	pub, err := ParsePublicKey(stmt.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := Verify(e, pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func payloadKeyID(canonical []byte) (string, error) {
	v, err := jcs.Parse(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: payload is not an object", ErrMalformed)
	}
	id, ok := obj["key_id"].(string)
	if !ok {
		return "", fmt.Errorf("%w: payload.key_id missing or not a string", ErrMalformed)
	}
	return id, nil
}
