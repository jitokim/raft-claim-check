package app

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jitokim/raft-claim-check/cli/internal/jcs"
	"github.com/jitokim/raft-claim-check/cli/internal/receipt"
)

// cmdVerify checks a receipt offline. It never calls Raft.
func (a *app) cmdVerify(args []string) int {
	fset := flag.NewFlagSet("claim-check verify", flag.ContinueOnError)
	fset.SetOutput(a.Stderr)
	pubFlag := fset.String("public-key", "", "the signer's public key (ed25519:...), from 'claim-check key show'")
	pos, code, ok := a.parse(fset, args, false)
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageErr("usage: claim-check verify <receipt.json> [--public-key <ed25519:...>]")
	}
	var data []byte
	var err error
	if pos[0] == "-" {
		data, err = io.ReadAll(a.Stdin)
	} else {
		data, err = os.ReadFile(pos[0])
	}
	if err != nil {
		a.logf("verify: %v", err)
		return ExitFailure
	}

	// Strict parse (duplicate keys, floats and out-of-range integers are
	// refused), then JCS is recomputed from the parsed payload.
	env, claimedID, err := receipt.FindEnvelope(data)
	if err != nil {
		return a.verifyFail("%v", err)
	}
	var head struct {
		Schema string `json:"schema"`
	}
	_ = json.Unmarshal(env.Payload, &head)
	isRegistration := head.Schema == receipt.SchemaRegistration
	if !isRegistration && head.Schema != receipt.SchemaReceipt {
		return a.verifyFail("unsupported payload.schema %q", head.Schema)
	}
	id := env.ReceiptID()
	if claimedID != "" && claimedID != id {
		return a.verifyFail("receipt_id %s does not match the payload, which gives %s", claimedID, id)
	}

	var pub ed25519.PublicKey
	switch {
	case *pubFlag != "":
		if pub, err = receipt.ParsePublicKey(*pubFlag); err != nil {
			return a.usageErr("--public-key: %v", err)
		}
	case isRegistration:
		if pub, err = receipt.ParsePublicKey(registrationKey(env)); err != nil {
			return a.verifyFail("statement public_key: %v", err)
		}
	default:
		s := ledgerKey(data)
		if s == "" {
			return a.usageErr("verify needs --public-key for a receipt without ledger.key.public_key")
		}
		if pub, err = receipt.ParsePublicKey(s); err != nil {
			return a.verifyFail("ledger.key.public_key: %v", err)
		}
		a.logf("warning: using ledger.key.public_key, which the app supplied; pass --public-key from 'claim-check key show' for an independent check")
	}
	if err := receipt.Verify(env, pub); err != nil {
		return a.verifyFail("%v", err)
	}

	if isRegistration {
		a.printf("OK: registration statement signed by %s (signature valid over JCS(payload))\n", receipt.KeyID(pub))
	} else {
		a.printf("OK: receipt %s signed by %s (signature valid over JCS(payload), receipt_id matches)\n", id, receipt.KeyID(pub))
	}
	return ExitOK
}

func (a *app) verifyFail(format string, args ...any) int {
	a.logf("verify FAILED: "+format, args...)
	return ExitFailure
}

func (a *app) printf(format string, args ...any) {
	fmt.Fprintf(a.Stdout, format, args...)
}

func registrationKey(env receipt.Envelope) string {
	var stmt receipt.Registration
	_ = json.Unmarshal(env.Payload, &stmt)
	return stmt.PublicKey
}

// ledgerKey returns ledger.key.public_key of a stored receipt, if present.
func ledgerKey(data []byte) string {
	v, err := jcs.Parse(data)
	if err != nil {
		return ""
	}
	obj, _ := v.(map[string]any)
	ledger, _ := obj["ledger"].(map[string]any)
	key, _ := ledger["key"].(map[string]any)
	s, _ := key["public_key"].(string)
	return s
}
