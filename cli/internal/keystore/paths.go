// Package keystore owns the CLI's files on disk: where they live for one
// (server, agent) pair, the private key file and key.json, and the spool
// directories. It never prints or logs private key material.
package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppDir is the directory name under the XDG config and state homes.
const AppDir = "claim-check"

// Modes for everything the CLI creates.
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// LookupEnv has the signature of os.LookupEnv, so tests can supply their own.
type LookupEnv func(key string) (string, bool)

// Paths are the resolved locations for one (server_id, agent_id) pair.
type Paths struct {
	ConfigDir   string // $XDG_CONFIG_HOME/claim-check/<server_id>/<agent_id>
	StateDir    string // $XDG_STATE_HOME/claim-check/<server_id>/<agent_id>
	KeyDir      string // ConfigDir/key
	KeyFile     string // ConfigDir/key/ed25519 (raw 32-byte seed)
	MetaFile    string // ConfigDir/key/key.json
	SpoolDir    string // StateDir/spool
	RejectedDir string // StateDir/spool/rejected
}

// ErrNoHome means neither the XDG variable nor HOME gave an absolute path.
var ErrNoHome = errors.New("keystore: no usable XDG base directory or HOME")

// ErrBadID means a server or agent ID cannot be used as a path segment.
var ErrBadID = errors.New("keystore: ID is not a safe path segment")

// Resolve derives the paths for (serverID, agentID) from the environment
// alone. Config is $XDG_CONFIG_HOME, else $HOME/.config; state is
// $XDG_STATE_HOME, else $HOME/.local/state. As the XDG spec says, a
// relative value is ignored. Two pairs never share a directory.
func Resolve(env LookupEnv, serverID, agentID string) (Paths, error) {
	for _, id := range []string{serverID, agentID} {
		if err := checkID(id); err != nil {
			return Paths{}, err
		}
	}
	configBase, err := xdgBase(env, "XDG_CONFIG_HOME", ".config")
	if err != nil {
		return Paths{}, err
	}
	stateBase, err := xdgBase(env, "XDG_STATE_HOME", filepath.Join(".local", "state"))
	if err != nil {
		return Paths{}, err
	}
	config := filepath.Join(configBase, AppDir, serverID, agentID)
	state := filepath.Join(stateBase, AppDir, serverID, agentID)
	key := filepath.Join(config, "key")
	spool := filepath.Join(state, "spool")
	return Paths{
		ConfigDir:   config,
		StateDir:    state,
		KeyDir:      key,
		KeyFile:     filepath.Join(key, "ed25519"),
		MetaFile:    filepath.Join(key, "key.json"),
		SpoolDir:    spool,
		RejectedDir: filepath.Join(spool, "rejected"),
	}, nil
}

func xdgBase(env LookupEnv, name, homeRel string) (string, error) {
	if v, ok := env(name); ok && filepath.IsAbs(v) {
		return filepath.Clean(v), nil
	}
	if home, ok := env("HOME"); ok && filepath.IsAbs(home) {
		return filepath.Join(home, homeRel), nil
	}
	return "", fmt.Errorf("%w: %s is unset or relative and HOME is unset or relative", ErrNoHome, name)
}

// checkID accepts an ID only if it is one clean, non-hidden path segment.
func checkID(id string) error {
	if id == "" || id == "." || id == ".." || strings.HasPrefix(id, ".") ||
		strings.ContainsAny(id, "/\\\x00") {
		return fmt.Errorf("%w: %q", ErrBadID, id)
	}
	return nil
}

// SpoolFile is the pending spool path for a receipt ID.
func (p Paths) SpoolFile(receiptID string) string {
	return filepath.Join(p.SpoolDir, receiptID+".json")
}

// RejectedFile is the rejected spool path for a receipt ID.
func (p Paths) RejectedFile(receiptID string) string {
	return filepath.Join(p.RejectedDir, receiptID+".json")
}

// EnsureConfigDirs creates the config tree down to KeyDir with mode 0700.
func (p Paths) EnsureConfigDirs() error {
	return ensurePrivateDirs(filepath.Dir(filepath.Dir(p.ConfigDir)), p.KeyDir)
}

// EnsureStateDirs creates the state tree down to RejectedDir with mode 0700.
func (p Paths) EnsureStateDirs() error {
	return ensurePrivateDirs(filepath.Dir(filepath.Dir(p.StateDir)), p.RejectedDir)
}

// ensurePrivateDirs creates leaf and its parents. Every directory from root
// (the claim-check directory) down to leaf is set to 0700, including ones
// that already existed; directories above root are created but not chmodded.
func ensurePrivateDirs(root, leaf string) error {
	if err := os.MkdirAll(leaf, DirMode); err != nil {
		return fmt.Errorf("keystore: creating %s: %w", leaf, err)
	}
	for dir := leaf; ; dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, DirMode); err != nil {
			return fmt.Errorf("keystore: chmod %s: %w", dir, err)
		}
		if dir == root || dir == filepath.Dir(dir) {
			return nil
		}
	}
}
