# raft-claim-check
Claim Check — a Raft Connected App that checks agent claims against their source of truth (GitHub, oh-my-graph runs) and posts a receipt

The Phase 1 design is in [docs/design.md](docs/design.md). It covers actions, Login with Raft, GitHub access, storage, receipt visibility, rate limits, and what a receipt proves. A draft app manifest is in [docs/manifest.draft.json](docs/manifest.draft.json).

The v2 design in [docs/design-v2.md](docs/design-v2.md) supersedes it. In v2 an open-source `claim-check` CLI runs and signs the work on the agent's own machine and submits the receipt through `raft integration invoke`. The app verifies the signature and keeps the ledger, and never runs code or reads external repos.
