package keystore

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// Errors from key operations. A missing key wraps fs.ErrNotExist too.
var (
	ErrKeyExists    = errors.New("keystore: a key already exists for this profile")
	ErrNoKey        = errors.New("keystore: no key for this profile; run 'claim-check key init'")
	ErrInsecureMode = errors.New("keystore: key file permissions are too open")
	ErrBadKeyFile   = errors.New("keystore: key file is invalid")
)

// Key is a loaded signing key. It implements crypto.Signer. Its private half
// is unexported, and String and GoString print only the key ID, so a Key
// cannot leak through fmt or a log line.
type Key struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

var _ crypto.Signer = (*Key)(nil)

// NewKeyFromSeed builds a Key from a 32-byte seed (used by key loading and
// by the test-vector generator).
func NewKeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrBadKeyFile, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Key{priv: priv, pub: pub, keyID: receipt.KeyID(pub)}, nil
}

// Public returns the ed25519.PublicKey (crypto.Signer).
func (k *Key) Public() crypto.PublicKey { return k.pub }

// PublicKey returns the raw public key.
func (k *Key) PublicKey() ed25519.PublicKey { return k.pub }

// KeyID returns "ck_..." for this key.
func (k *Key) KeyID() string { return k.keyID }

// Sign signs message with plain Ed25519 (crypto.Signer; opts must be
// crypto.Hash(0)).
func (k *Key) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.priv.Sign(rand, message, opts)
}

func (k *Key) String() string   { return "keystore.Key{" + k.keyID + "}" }
func (k *Key) GoString() string { return k.String() }

// Meta is key.json: the public half and the binding stored at key register.
// BoundTo is null until the key is registered.
type Meta struct {
	KeyID     string           `json:"key_id"`
	PublicKey string           `json:"public_key"`
	BoundTo   *receipt.BoundTo `json:"bound_to"`
}

// Generate creates a new key: it reads a 32-byte seed from rand
// (crypto/rand.Reader in production), writes it with O_CREAT|O_EXCL and mode
// 0600, and writes key.json without a binding. It refuses if a key file
// already exists and never returns or prints the seed.
func Generate(p Paths, rand io.Reader) (*Key, error) {
	if err := p.EnsureConfigDirs(); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, fmt.Errorf("keystore: reading random seed: %w", err)
	}
	key, err := NewKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, FileMode)
	if errors.Is(err, fs.ErrExist) {
		return nil, ErrKeyExists
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: creating key file: %w", err)
	}
	if _, err := f.Write(seed); err != nil {
		f.Close()
		os.Remove(p.KeyFile)
		return nil, fmt.Errorf("keystore: writing key file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(p.KeyFile)
		return nil, fmt.Errorf("keystore: writing key file: %w", err)
	}
	meta := Meta{KeyID: key.KeyID(), PublicKey: receipt.EncodePublicKey(key.pub)}
	if err := SaveMeta(p, meta); err != nil {
		return nil, err
	}
	return key, nil
}

// Load reads the private key. It refuses a key file that is not a regular
// file (including a symlink), whose mode grants any group or other
// permission, or that is not exactly 32 bytes.
func Load(p Paths) (*Key, error) {
	seed, err := readPrivate(p.KeyFile, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrBadKeyFile, p.KeyFile, len(seed), ed25519.SeedSize)
	}
	return NewKeyFromSeed(seed)
}

// LoadMeta reads key.json with the same mode check as the key file.
func LoadMeta(p Paths) (Meta, error) {
	data, err := readPrivate(p.MetaFile, 64*1024)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("%w: %s: %v", ErrBadKeyFile, p.MetaFile, err)
	}
	return m, nil
}

// SaveMeta writes key.json atomically (temporary file, then rename) with
// mode 0600.
func SaveMeta(p Paths, m Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(p.KeyDir, ".key.json.*")
	if err != nil {
		return fmt.Errorf("keystore: writing key.json: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(FileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: writing key.json: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: writing key.json: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: writing key.json: %w", err)
	}
	if err := os.Rename(tmp.Name(), p.MetaFile); err != nil {
		return fmt.Errorf("keystore: writing key.json: %w", err)
	}
	return nil
}

// readPrivate opens path without following a symlink, checks the mode on the
// open descriptor, and reads at most limit+1 bytes.
func readPrivate(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w (%s): %w", ErrNoKey, filepath.Base(path), fs.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %v", ErrBadKeyFile, path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadKeyFile, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrBadKeyFile, path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; it must not grant group or other access (run: chmod 600 %s)",
			ErrInsecureMode, path, perm, path)
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
