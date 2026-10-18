# Plan: Vault v1 (issue #19)

## Strategy

Port lambdasistemi/singular `origin/main` @ `4ba0f5b4`
(`offchain/cli/src/Singular/CLI/Vault.hs`, `Passphrase.hs`,
`offchain/test/Singular/CLI/VaultSpec.hs`) into the ledger-free core,
keeping this repository's key representation (crypton Ed25519) instead
of singular's `cardano-crypto-class`. Replace the opaque-bytes vault
(`encryptVault`/`decryptVault`) and the `--passphrase-file` source in
the same diff (swap rule): no old path survives.

Add the tx-sign JSON payload to the reader only. Its format is
cardano-tx-tools `origin/main` @ `1b623b1`,
`src/Cardano/Tx/Sign/Vault.hs` (`decodeWitnessVault`,
`encodeWitnessVault`); only the `cardano-cli-skey` source kind is read.

## Constraints

- Library stays ledger-free (`core-stays-ledger-free`).
- Stock `age` is a test-time dependency: present in the dev shell
  (`just ci`), in the hosted `nix run .#unit-tests` app, and in the
  flake's `checks.unit`. The age-interop examples fail (never skip)
  when `age` is absent.
- Fixtures are produced by real tools and their provenance is
  committed beside them: `cardano-cli` 10.15.1.0
  (`/nix/store/bz64647x6q7ghmdqlax7nb08a9l0gfn6-cardano-cli-exe-cardano-cli-10.15.1.0/bin/cardano-cli`)
  for the key pair; the tx-sign fixture from the cardano-tx-tools
  payload format, encrypted at work factor ≤ 18, with the exact
  commands recorded.
- Every new example lives under the hspec path `vault v1` with the
  sub-paths `age interop`, `tx-sign payload`, `work factor cap`,
  `exclusive creation`, `passphrase intake`, `hidden terminal`,
  `command line`, so the gate selects with `--match`.

## Slices

One slice, one behaviour commit: `vault-v1` (all tasks in
`tasks.md`). Bisect-safe as a unit: the CLI flag change, library
swap, tests, fixtures and flake test inputs land together.

## Gate

T.O.-authored (no gate authors in the operator roster), frozen in the
ticket runtime root (`gate-v1.md`), hash in ticket STATUS.
`nix develop --quiet -c just ci` runs once on the final candidate.
