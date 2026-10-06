// Command claim-check runs a command (or hashes a file) on the agent's own
// machine, signs a receipt of it, and submits the receipt to the Claim Check
// app through `raft integration invoke`. See README.md and
// docs/design-v2.md.
package main

import (
	"os"

	"github.com/jitokim/raft-claim-check/cli/internal/app"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "2.0.0-dev"

func main() {
	os.Exit(app.Main(os.Args[1:], app.DefaultDeps(version)))
}
