# Plan (#20)

## Strategy

Port singular `origin/main` `a1cb80cc` modules
`offchain/local-services/Singular/Registry/{Bundle,Submit,Signing}.hs` and
specs `offchain/test/Singular/Registry/{BundleSpec,SubmitSpec}.hs` into a
new public sublibrary, replacing `Cardano.Tx.Ledger (ConwayTx)` with the
ledger's own `Tx ConwayEra`, and singular's `LedgerProvider`
`ChainPoint`/`InclusionStatus` with planner-owned types.

## Build plumbing (constraints)

- Pin CHaP exactly as cardano-tx-tools `origin/main` `1b623b1` does
  (same `cardano-haskell-packages` index-state `2026-03-23T18:21:55Z`, same
  CHaP flake input revision, same hackage index-state, GHC `ghc9123`), so a
  downstream consumer resolves one ledger plan.
- No `source-repository-package` for cardano-tx-tools or
  cardano-node-clients.
- Edits to `cardano-wallet-tools.cabal`, `flake.nix`, `app/Main.hs` stay
  additive and local (#21 edits the same files in parallel).
- Every new test runs in a hosted CI job; a new test-suite or flake app is
  wired into `.github/workflows/ci.yml` in the same diff.

## Slices

One slice, `ledger-bundle-planner`, OWNER. Checkpoints for the persistent
auditor: RED bundle; acceptance line 1 GREEN; line 3 GREEN; line 2
(docs) GREEN; pre-push.

## Live boundaries

None: the library is pure, `cwt bundle check` reads one file.
