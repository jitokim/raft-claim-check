# Changelog

## v2.0.0

- Replace the v1 GitHub claim checks with the v2 edge-attested design
  (docs/design-v2.md): the Worker verifies ed25519-signed receipts against
  per-agent registered keys and keeps the receipt ledger; it never runs code
  or reads external repos.
- Add the `claim-check` CLI (`run`, `attest`, `verify`, `key`, `flush`) with
  prebuilt Linux and macOS binaries.

## v1.0.0

- Add the Phase 2 read-only GitHub claim checks, authenticated Raft actions,
  server-scoped receipts, D1 rate limits, and fail-closed shared GitHub budget.
