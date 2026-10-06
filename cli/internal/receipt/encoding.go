// Package receipt holds the Claim Check v2 wire format: the value encodings,
// receipt and key IDs, the typed signed payloads, and the signed envelope.
// Everything here follows docs/design-v2.md, "## Receipt schema" and
// "## Key lifecycle".
package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Prefixes of the encoded values.
const (
	PublicKeyPrefix = "ed25519:"
	SignaturePrefix = "ed25519:"
	HashPrefix      = "sha256:"
	ReceiptIDPrefix = "rcpt_"
	KeyIDPrefix     = "ck_"
)

// NonceSize is the number of random bytes in a payload or statement nonce.
const NonceSize = 16

// TimeLayout is RFC 3339 UTC with exactly three fractional digits.
const TimeLayout = "2006-01-02T15:04:05.000Z"

var (
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	b64 = base64.RawURLEncoding.Strict()
)

// ErrEncoding is wrapped by every decoding error in this file.
var ErrEncoding = errors.New("receipt: bad encoding")

// shortID is lowercase unpadded base32 of the first 16 bytes of SHA-256(b).
func shortID(b []byte) string {
	sum := sha256.Sum256(b)
	return strings.ToLower(b32.EncodeToString(sum[:16]))
}

// ReceiptID returns "rcpt_" + base32 of SHA-256(jcsPayload)[:16]. The
// argument must be the JCS bytes of the payload.
func ReceiptID(jcsPayload []byte) string { return ReceiptIDPrefix + shortID(jcsPayload) }

// KeyID returns "ck_" + base32 of SHA-256(raw 32-byte public key)[:16].
func KeyID(pub ed25519.PublicKey) string { return KeyIDPrefix + shortID(pub) }

// HashBytes returns "sha256:" + lowercase hex of SHA-256(b).
func HashBytes(b []byte) string { return FormatHash(sha256.Sum256(b)) }

// FormatHash returns "sha256:" + lowercase hex of a finished digest, for
// callers that hash a stream with crypto/sha256 themselves.
func FormatHash(sum [sha256.Size]byte) string { return HashPrefix + hex.EncodeToString(sum[:]) }

// EncodePublicKey returns "ed25519:" + unpadded base64url of the raw key.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return PublicKeyPrefix + b64.EncodeToString(pub)
}

// ParsePublicKey decodes an "ed25519:" public key. It rejects padding,
// non-canonical trailing bits and any length other than 32 bytes.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := decodePrefixed(s, PublicKeyPrefix, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return ed25519.PublicKey(raw), nil
}

// EncodeSignature returns "ed25519:" + unpadded base64url of a signature.
func EncodeSignature(sig []byte) string { return SignaturePrefix + b64.EncodeToString(sig) }

// ParseSignature decodes an "ed25519:" signature with the same strictness as
// ParsePublicKey, requiring 64 bytes.
func ParseSignature(s string) ([]byte, error) {
	raw, err := decodePrefixed(s, SignaturePrefix, ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return raw, nil
}

func decodePrefixed(s, prefix string, size int) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrEncoding, prefix)
	}
	raw, err := b64.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: not unpadded canonical base64url", ErrEncoding)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrEncoding, len(raw), size)
	}
	return raw, nil
}

// NewNonce reads NonceSize bytes from r (crypto/rand.Reader in production)
// and returns them as unpadded base64url (22 characters).
func NewNonce(r io.Reader) (string, error) {
	b := make([]byte, NonceSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("receipt: reading nonce: %w", err)
	}
	return b64.EncodeToString(b), nil
}

// FormatTime renders t as RFC 3339 UTC with milliseconds, truncating (not
// rounding) anything finer, e.g. 2026-10-06T09:00:03.120Z.
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(TimeLayout)
}

// ParseTime accepts only the exact form FormatTime produces.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, fmt.Errorf("%w: time %q is not RFC 3339 UTC with milliseconds", ErrEncoding, s)
	}
	return t, nil
}
