// Package spool stores receipts that are not yet accepted by the app:
// spool/<receipt_id>.json (pending) and spool/rejected/<receipt_id>.json.
// A pending file holds the exact submit_receipt request body,
// {"receipt": {"payload": ..., "signature": ...}}, serialized as JCS.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// Ages from the design's "## Storage".
const (
	MaxPendingAge  = 7 * 24 * time.Hour
	MaxRejectedAge = 30 * 24 * time.Hour
)

// Body returns the submit_receipt request body for env: {"receipt": env}.
func Body(env receipt.Envelope) ([]byte, error) {
	inner, err := env.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(`{"receipt":`), inner...), '}'), nil
}

// Write stores env as a pending receipt (mode 0600, atomic) and returns the
// entry as read back from disk.
func Write(p keystore.Paths, env receipt.Envelope) (Entry, error) {
	if err := p.EnsureStateDirs(); err != nil {
		return Entry{}, err
	}
	body, err := Body(env)
	if err != nil {
		return Entry{}, err
	}
	path := p.SpoolFile(env.ReceiptID())
	if err := writeAtomic(p.SpoolDir, path, body); err != nil {
		return Entry{}, err
	}
	return read(path)
}

// Entry is one pending receipt.
type Entry struct {
	ID       string // computed from the payload
	Path     string
	Body     []byte
	KeyID    string
	SignedAt time.Time
}

// List returns the pending receipts, oldest signed_at first (ties by ID),
// and the paths of pending files that cannot be read as a receipt.
func List(p keystore.Paths) (entries []Entry, bad []string, err error) {
	names, err := os.ReadDir(p.SpoolDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, de := range names {
		name := de.Name()
		if !de.Type().IsRegular() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(p.SpoolDir, name)
		e, err := read(path)
		if err != nil {
			bad = append(bad, path)
			continue
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].SignedAt.Equal(entries[j].SignedAt) {
			return entries[i].SignedAt.Before(entries[j].SignedAt)
		}
		return entries[i].ID < entries[j].ID
	})
	return entries, bad, nil
}

func read(path string) (Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, err
	}
	env, _, err := receipt.FindEnvelope(data)
	if err != nil {
		return Entry{}, err
	}
	var head struct {
		KeyID    string `json:"key_id"`
		SignedAt string `json:"signed_at"`
	}
	if err := json.Unmarshal(env.Payload, &head); err != nil {
		return Entry{}, err
	}
	signed, err := receipt.ParseTime(head.SignedAt)
	if err != nil {
		return Entry{}, err
	}
	body, err := Body(env)
	if err != nil {
		return Entry{}, err
	}
	return Entry{ID: env.ReceiptID(), Path: path, Body: body, KeyID: head.KeyID, SignedAt: signed}, nil
}

// Remove deletes a pending receipt after the app stored it.
func Remove(e Entry) error {
	if err := os.Remove(e.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Rejection is why a receipt was moved to rejected/.
type Rejection struct {
	Status     int    `json:"status"` // 0 when the CLI rejected it locally
	Error      string `json:"error"`
	Hint       string `json:"hint"`
	RejectedAt string `json:"rejected_at"`
}

// Reject moves a pending receipt to rejected/<id>.json as
// {"receipt": envelope, "rejection": {status, error, hint, rejected_at}}.
// The file's mtime is set to now, which PurgeRejected measures from.
func Reject(p keystore.Paths, e Entry, r Rejection, now time.Time) error {
	if err := p.EnsureStateDirs(); err != nil {
		return err
	}
	r.RejectedAt = receipt.FormatTime(now)
	var body map[string]any
	if v, err := jcs.Parse(e.Body); err == nil {
		body, _ = v.(map[string]any)
	}
	if body == nil {
		return fmt.Errorf("spool: %s is not a receipt body", e.Path)
	}
	body["rejection"] = map[string]any{
		"status": int64(r.Status), "error": r.Error, "hint": r.Hint, "rejected_at": r.RejectedAt,
	}
	data, err := jcs.Encode(body)
	if err != nil {
		return err
	}
	dst := p.RejectedFile(e.ID)
	if err := writeAtomic(p.RejectedDir, dst, data); err != nil {
		return err
	}
	_ = os.Chtimes(dst, now, now)
	return Remove(e)
}

// Quarantine moves an unreadable pending file into rejected/ unchanged.
func Quarantine(p keystore.Paths, path string, now time.Time) error {
	if err := p.EnsureStateDirs(); err != nil {
		return err
	}
	dst := filepath.Join(p.RejectedDir, filepath.Base(path))
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	_ = os.Chtimes(dst, now, now)
	return nil
}

// PurgeRejected deletes rejected files whose mtime is more than 30 days
// before now, and returns how many it deleted.
func PurgeRejected(p keystore.Paths, now time.Time) (int, error) {
	names, err := os.ReadDir(p.RejectedDir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, de := range names {
		if !de.Type().IsRegular() {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > MaxRejectedAge {
			if os.Remove(filepath.Join(p.RejectedDir, de.Name())) == nil {
				n++
			}
		}
	}
	return n, nil
}

func writeAtomic(dir, dst string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if err := tmp.Chmod(keystore.FileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("spool: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("spool: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	return nil
}
