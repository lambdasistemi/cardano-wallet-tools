# cardano-wallet-tools Constitution

Authoritative source for architectural decisions. Feature plans must
include a Constitution Check before research and re-check it after
design. Last updated: 2026-06-22.

## Purpose

`cardano-wallet-tools` is an operator wallet-UTxO toolkit and a
PureScript CIP-30 browser wallet built over one pure Haskell core. It
owns the wallet-side concerns that general tx tooling leaves out:
trust-minimized UTxO resolution, coin and **collateral** selection,
wallet consolidation / collateral provisioning, balancing, and UTxO
reporting. Transaction assembly and balancing primitives are delegated
to [`cardano-tx-tools`](https://github.com/lambdasistemi/cardano-tx-tools);
this project never re-implements the Conway wire format.

## Architecture

One pure Haskell **core**, two frontends:

- **Native operator CLI(s)** — `resolve`, `utxo-report`,
  `select-collateral`, `consolidate` / `provision-collateral`,
  `balance`, `submit`.
- **Haskell → WASM** module consumed by a **PureScript + CIP-30**
  browser wallet (spago / esbuild / Halogen).

Both frontends share the same pure core, so the browser gets the same
guarantees as the CLI.

## Core Principles

### I. Pure core, impure shell

Selection, collateral computation, balancing math, and CBOR
verification are pure: no `IO`, networking, filesystem, time, or
non-determinism. Effects (node sockets, HTTP, signing) live only in
per-backend shells and the CLI. This is what makes the core portable
and testable.

### II. WASM/JS portability is a hard target

The core MUST cross-compile to GHC-WASM and GHC-JS — the browser
wallet depends on it. A dependency that does not cross-compile is not
admitted to the core. Browser and CLI run the same selection and
verification code.

### III. Ledger-native types

Use `cardano-ledger` types (via `cardano-tx-tools`); never introduce a
shadow ledger representation. Value, `TxIn`, `TxOut`, and CBOR
encodings stay ledger-faithful so verification matches what the node
checks.

### IV. Trust-minimized UTxO resolution

The `TxIn -> TxOut` backend is pluggable (N2C / Blockfrost / Koios) and
tiered by trust:

- **N2C (own node): trusted.** `LocalStateQuery` is authoritative.
- **Blockfrost / Koios: untrusted, therefore verified.** Never trust
  the API's structured UTxO JSON. Fetch the producing transaction's
  raw CBOR, recompute `blake2b-256(canonical tx body)`, assert it
  equals the `TxIn`'s txid (`ResolveHashMismatch` otherwise), then read
  `outputs[ix]` from the verified body.

The verifier (`TxIn -> TxCbor -> Either ResolveError TxOut`) is pure and
lives in the core, so the browser path inherits the same guarantee.
Protocol parameters are **best-effort** from the backend: a wrong value
only mis-sizes fee/collateral, and the node re-validates at submit, so
funds cannot be stolen — but this weaker guarantee is documented, not
hidden.

### V. cardano-tx-tools is the single source of truth for assembly

CBOR encoding, the build DSL, fee estimation, and balancing come from
`cardano-tx-tools`. This project supplies correct **inputs** and
**collateral** to that machinery; it does not duplicate it.

### VI. Build-only by default; keys stay out of the core

The core produces unsigned (or partially built) transactions and never
holds key material. The browser signs via CIP-30 `signTx`; the CLI may
optionally sign via an age-encrypted vault for unattended flows.

### VII. Service boundaries are records of functions

Backends and effectful boundaries are records of functions, not
typeclasses (e.g. `ResolveBackend`, `SubmitBackend`).

### VIII. Invariants first, proved then tested

Selection invariants are stated precisely, optionally formalized in
`lean/`, and mirrored as QuickCheck properties:

- Collateral: the returned set covers the required total **or** an
  explicit shortfall is reported; never silently under-provision.
- Collateral respects `maxCollateralInputs`.
- Native-asset collateral_return conserves all collateral-input assets.
- Coin selection covers `outputs + fee` or reports a shortfall.

## Domain Constraints

- **Collateral selection**: largest-first to `ceil(fee * pct / 100)`,
  capped at `maxCollateralInputs`, native-asset-aware return; on
  exhaustion report `selected count + sum vs required`, never a bare
  failure. CIP-30 `getCollateral` is intentionally bypassed (too
  limited); collateral is selected from the full UTxO set.
- **Coin selection**: pluggable strategy — `LargestFirst` default;
  `RandomImprove` opt-in and seeded for WASM determinism.
- **Submission**: symmetric across N2C / Blockfrost / Koios / CIP-30,
  with confirm-on-chain (poll for the txid or time out). No multisig in
  v1 — co-signing is handed off to `cardano-tx-tools` / amaru.
- **Networks**: all, parameterized by network magic.
- **I/O formats**: TextEnvelope and raw CBOR hex; interoperate with
  `cardano-tx-tools` verbs (`tx-inspect`, `tx-validate`, `tx-sign`).

## Development Workflow

- **Nix-first**: `flake.nix` (haskell.nix, GHC 9.12.3) provides every
  tool; CI and local use the same shell. `runs-on: nixos`.
- **just recipes**: `build`, `unit`, `format`, `format-check`,
  `hlint`, `cabal-check`, `ci`, docs recipes. Always run `just ci`
  before pushing.
- **Formatting**: Fourmolu, 70-char lines, leading commas/arrows.
  HLint clean. `cabal check` Hackage-ready (`-Werror` behind a
  `werror` flag, `base < 5`, synopsis <= 80).
- **Speckit** for every feature: specify -> plan -> tasks -> implement.
  This constitution gates planning.
- **Linear history**: rebase merge; Conventional Commits; one concern
  per commit; bisect-safe slices.

## Governance

This constitution is authoritative on architectural conflict.
Amendments land via PR. Any dependency admitted to the **core** must be
shown to cross-compile to GHC-WASM and GHC-JS first (Principle II).

**Version**: 0.1.0 | **Ratified**: 2026-06-22 | **Last amended**: 2026-06-22
