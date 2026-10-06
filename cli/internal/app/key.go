package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/keystore"
	"github.com/jitokim/raft-claim-check/cli/internal/raft"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
	"github.com/jitokim/raft-claim-check/cli/internal/spool"
)

// exitError carries an exit code with a message for key commands.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func (a *app) fail(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		a.logf("%s", ee.msg)
		return ee.code
	}
	a.logf("%v", err)
	return ExitFailure
}

// call invokes action and returns the result of a 200 or 201. Other
// outcomes become an *exitError: 78 when Raft is missing or not logged in,
// 75 when the call may succeed later, 1 when the app refused.
func (a *app) call(p *profile, action string, body []byte) (int, []byte, error) {
	login := fmt.Sprintf("hint: run 'raft integration login --service %s'", p.service)
	status, result, err := p.raft.Invoke(action, body)
	switch {
	case errors.Is(err, raft.ErrNotInstalled):
		return 0, nil, &exitError{ExitConfig, fmt.Sprintf("%s: %v; hint: this machine needs a Raft CLI with Agent Login", action, err)}
	case errors.Is(err, raft.ErrNotLoggedIn):
		return 0, nil, &exitError{ExitConfig, fmt.Sprintf("%s: %v; %s", action, err, login)}
	case err != nil:
		return 0, nil, &exitError{ExitTempFail, fmt.Sprintf("%s: outcome unknown: %v", action, err)}
	case status == 200 || status == 201:
		return status, result, nil
	}
	msg := fmt.Sprintf("%s: %s", action, statusLine(status, result))
	if ae, ok := parseAppError(result); ok && ae.Hint != "" {
		msg += ": " + ae.Hint
	}
	switch {
	case status == 401:
		return 0, nil, &exitError{ExitConfig, msg + "; " + login}
	case status == 429 || status >= 500:
		return 0, nil, &exitError{ExitTempFail, msg + "; try again later"}
	}
	return 0, nil, &exitError{ExitFailure, msg}
}

func (a *app) cmdKeyInit(args []string) int {
	fset, svc := a.newFlags("key init")
	if pos, code, ok := a.parse(fset, args, false); !ok || len(pos) > 0 {
		if ok {
			return a.usageErr("usage: claim-check key init")
		}
		return code
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	key, err := keystore.Generate(p.paths, a.Rand)
	if errors.Is(err, keystore.ErrKeyExists) {
		a.logf("a key already exists at %s; refusing to replace it (use 'claim-check key rotate')", p.paths.KeyFile)
		return ExitFailure
	}
	if err != nil {
		return a.fail(err)
	}
	a.printf("key_id      %s\npublic_key  %s\n", key.KeyID(), receipt.EncodePublicKey(key.PublicKey()))
	a.logf("created %s; next: 'claim-check key register'", p.paths.KeyFile)
	return ExitOK
}

func (a *app) cmdKeyRegister(args []string) int {
	fset, svc := a.newFlags("key register")
	label := fset.String("label", "", "a label for this key, shown by 'key list'")
	pos, code, ok := a.parse(fset, args, false)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("usage: claim-check key register [--label <text>]")
	}
	labelSet := false
	fset.Visit(func(f *flag.Flag) { labelSet = labelSet || f.Name == "label" })
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	key, _, code := a.loadKey(p, false)
	if key == nil {
		return code
	}
	var l *string
	if labelSet {
		l = label
	}
	bound, err := a.register(p, key, l)
	if err != nil {
		return a.fail(err)
	}
	a.printf("registered %s to server %s, principal %s\n", key.KeyID(), bound.ServerID, bound.PrincipalID)
	return ExitOK
}

// register proves possession of key and binds it to the session's server
// and principal (get_session, then register_key), then stores the binding.
func (a *app) register(p *profile, key *keystore.Key, label *string) (*receipt.BoundTo, error) {
	_, result, err := a.call(p, "get_session", []byte("{}"))
	if err != nil {
		return nil, err
	}
	var sess struct {
		Principal struct{ ID string } `json:"principal"`
		Server    struct{ ID string } `json:"server"`
	}
	if json.Unmarshal(result, &sess) != nil || sess.Principal.ID == "" || sess.Server.ID == "" {
		return nil, &exitError{ExitTempFail, "get_session: the response has no principal.id and server.id"}
	}
	nonce, err := receipt.NewNonce(a.Rand)
	if err != nil {
		return nil, err
	}
	stmt := receipt.NewRegistration(key.PublicKey(), sess.Server.ID, sess.Principal.ID, a.Now(), nonce, label, a.Version)
	env, err := receipt.Sign(key, stmt)
	if err != nil {
		return nil, err
	}
	inner, err := env.MarshalJSON()
	if err != nil {
		return nil, err
	}
	body := append(append([]byte(`{"registration":`), inner...), '}')
	_, result, err = a.call(p, "register_key", body)
	if err != nil {
		return nil, err
	}
	var rec struct {
		KeyID string `json:"key_id"`
	}
	if json.Unmarshal(result, &rec) != nil || rec.KeyID != key.KeyID() {
		return nil, &exitError{ExitTempFail, fmt.Sprintf("register_key: the response does not name key %s", key.KeyID())}
	}
	bound := &receipt.BoundTo{ServerID: sess.Server.ID, PrincipalID: sess.Principal.ID}
	meta := keystore.Meta{KeyID: key.KeyID(), PublicKey: receipt.EncodePublicKey(key.PublicKey()), BoundTo: bound}
	if err := keystore.SaveMeta(p.paths, meta); err != nil {
		return nil, err
	}
	return bound, nil
}

func (a *app) cmdKeyShow(args []string) int {
	fset, svc := a.newFlags("key show")
	if pos, code, ok := a.parse(fset, args, false); !ok || len(pos) > 0 {
		if ok {
			return a.usageErr("usage: claim-check key show")
		}
		return code
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	_, meta, code := a.loadKey(p, false)
	if code != 0 {
		return code
	}
	bound := "not registered (run 'claim-check key register')"
	if meta.BoundTo != nil {
		bound = fmt.Sprintf("server %s, principal %s", meta.BoundTo.ServerID, meta.BoundTo.PrincipalID)
	}
	a.printf("key_id      %s\npublic_key  %s\nbound_to    %s\nkey_file    %s\n", meta.KeyID, meta.PublicKey, bound, p.paths.KeyFile)
	return ExitOK
}

func (a *app) cmdKeyList(args []string) int {
	fset, svc := a.newFlags("key list")
	if pos, code, ok := a.parse(fset, args, false); !ok || len(pos) > 0 {
		if ok {
			return a.usageErr("usage: claim-check key list")
		}
		return code
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	local := ""
	if meta, err := keystore.LoadMeta(p.paths); err == nil {
		local = meta.KeyID
	}
	_, result, err := a.call(p, "list_keys", []byte("{}"))
	if err != nil {
		return a.fail(err)
	}
	var list struct {
		Keys []struct {
			KeyID            string  `json:"key_id"`
			Label            *string `json:"label"`
			Status           string  `json:"status"`
			RegisteredAt     string  `json:"registered_at"`
			RevokedAt        *string `json:"revoked_at"`
			RevokedReason    *string `json:"revoked_reason"`
			CompromisedSince *string `json:"compromised_since"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(result, &list); err != nil {
		a.logf("list_keys: unexpected response: %v", err)
		return ExitFailure
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\tKEY_ID\tSTATUS\tLABEL\tREGISTERED_AT\tREVOKED_AT\tREASON\tCOMPROMISED_SINCE")
	for _, k := range list.Keys {
		mark := ""
		if k.KeyID == local {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", mark, k.KeyID, k.Status, orDash(k.Label),
			k.RegisteredAt, orDash(k.RevokedAt), orDash(k.RevokedReason), orDash(k.CompromisedSince))
	}
	tw.Flush()
	return ExitOK
}

func orDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

func (a *app) cmdKeyRevoke(args []string) int {
	fset, svc := a.newFlags("key revoke")
	keyID := fset.String("key-id", "", "the key to revoke (default: this profile's key)")
	reason := fset.String("reason", "", "rotated, lost or compromised")
	since := fset.String("compromised-since", "", "RFC 3339 time; only with --reason compromised")
	pos, code, ok := a.parse(fset, args, false)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("usage: claim-check key revoke [--key-id <id>] --reason rotated|lost|compromised [--compromised-since <time>]")
	}
	switch *reason {
	case "rotated", "lost", "compromised":
	default:
		return a.usageErr("--reason must be rotated, lost or compromised")
	}
	body := map[string]any{"reason": *reason}
	if *since != "" {
		if *reason != "compromised" {
			return a.usageErr("--compromised-since is allowed only with --reason compromised")
		}
		t, err := parseRFC3339(*since)
		if err != nil {
			return a.usageErr("--compromised-since: %v", err)
		}
		body["compromised_since"] = receipt.FormatTime(t)
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	local, _ := keystore.LoadMeta(p.paths)
	if *keyID == "" {
		if local.KeyID == "" {
			a.logf("this profile has no key.json; pass --key-id (see 'claim-check key list')")
			return ExitConfig
		}
		*keyID = local.KeyID
	}
	body["key_id"] = *keyID
	if err := a.revoke(p, body); err != nil {
		return a.fail(err)
	}
	a.printf("revoked %s (reason %s)\n", *keyID, *reason)
	if *keyID == local.KeyID {
		// A revoked key can never be used again; drop it so 'key init' can
		// create a new one.
		removeKeyFiles(p.paths.KeyFile, p.paths.MetaFile)
		a.logf("removed the revoked local key; next: 'claim-check key init', then 'claim-check key register'")
	}
	return ExitOK
}

func (a *app) revoke(p *profile, body map[string]any) error {
	data, err := jcs.Encode(body)
	if err != nil {
		return err
	}
	_, _, err = a.call(p, "revoke_key", data)
	return err
}

func removeKeyFiles(paths ...string) {
	for _, path := range paths {
		_ = os.Remove(path)
	}
}

func (a *app) cmdKeyRotate(args []string) int {
	fset, svc := a.newFlags("key rotate")
	force := fset.Bool("force", false, "rotate even if receipts signed by the old key are pending (they are lost)")
	if pos, code, ok := a.parse(fset, args, false); !ok || len(pos) > 0 {
		if ok {
			return a.usageErr("usage: claim-check key rotate [--force]")
		}
		return code
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	oldKey, _, code := a.loadKey(p, true)
	if oldKey == nil {
		return code
	}
	oldID := oldKey.KeyID()

	if _, err := a.flush(p); err != nil {
		a.logf("flush: %v", err)
		return ExitFailure
	}
	entries, _, err := spool.List(p.paths)
	if err != nil {
		return a.fail(err)
	}
	pending := 0
	for _, e := range entries {
		if e.KeyID == oldID {
			pending++
		}
	}
	if pending > 0 && !*force {
		a.logf("refusing to rotate: %d receipt(s) signed by %s are still pending; nothing was changed", pending, oldID)
		a.logf("hint: run 'claim-check flush' once online, or 'claim-check key rotate --force' to lose them")
		return ExitTempFail
	}
	if pending > 0 {
		a.logf("--force: %d pending receipt(s) signed by %s will be refused and moved to spool/rejected/", pending, oldID)
	}

	// Set the old key aside so that key init can create the new one in place;
	// it is restored if the new key cannot be registered.
	oldKeyFile, oldMetaFile := p.paths.KeyFile+".old", p.paths.MetaFile+".old"
	if err := os.Rename(p.paths.KeyFile, oldKeyFile); err != nil {
		return a.fail(err)
	}
	if err := os.Rename(p.paths.MetaFile, oldMetaFile); err != nil {
		_ = os.Rename(oldKeyFile, p.paths.KeyFile)
		return a.fail(err)
	}
	restore := func() {
		removeKeyFiles(p.paths.KeyFile, p.paths.MetaFile)
		_ = os.Rename(oldKeyFile, p.paths.KeyFile)
		_ = os.Rename(oldMetaFile, p.paths.MetaFile)
	}
	newKey, err := keystore.Generate(p.paths, a.Rand)
	if err != nil {
		restore()
		return a.fail(err)
	}
	if _, err := a.register(p, newKey, nil); err != nil {
		restore()
		a.logf("could not register the new key; the old key %s is unchanged", oldID)
		return a.fail(err)
	}
	removeKeyFiles(oldKeyFile, oldMetaFile)
	a.printf("new key %s registered\n", newKey.KeyID())
	if err := a.revoke(p, map[string]any{"key_id": oldID, "reason": "rotated"}); err != nil {
		code := a.fail(err)
		a.logf("the old key %s is NOT revoked yet; run 'claim-check key revoke --key-id %s --reason rotated'", oldID, oldID)
		return code
	}
	a.printf("old key %s revoked (reason rotated) and deleted\n", oldID)
	return ExitOK
}

// parseRFC3339 accepts any RFC 3339 time.
func parseRFC3339(s string) (t time.Time, err error) {
	t, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	return t, err
}
