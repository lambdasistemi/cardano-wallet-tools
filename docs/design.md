# Design

This document captures the design agreed at project inception. The
[constitution](https://github.com/lambdasistemi/cardano-wallet-tools/blob/main/.specify/memory/constitution.md)
is the authoritative
short form; this is the narrative.

## Origin

A live `amaru-treasury-tx reorganize` failed with:

```
tx-build: reorganize failed while building the transaction:
collateral shortfall; required collateral lovelace: 17537408;
available collateral lovelace: 3709675
```

A reorganize spends many treasury UTxOs (each a Plutus execution), so
its fee is large (~11.7 ADA), and the ledger requires collateral =
`fee × 150%` ≈ 17.5 ADA. The builder pinned collateral to a single
wallet UTxO (3.7 ADA), the largest **pure-ADA** one available. No layer
selected collateral to a target, and `collateral_return` was ADA-only,
so token-bearing UTxOs were ineligible. `cardano-wallet-tools` exists to
make wallet-side selection — coin and collateral — a first-class,
verifiable concern.

## Mission

An operator wallet-UTxO toolkit plus a PureScript CIP-30 browser wallet,
over one pure Haskell core. Capabilities:

- **Coin + collateral selection** — input selection to cover
  `outputs + fee`; multi-UTxO, native-asset-aware collateral selection
  with a conserving `collateral_return`, capped at
  `maxCollateralInputs`, with explicit shortfall reporting.
- **Consolidation / provisioning** — build a defrag tx, or a
  send-to-self tx that mints a single fat pure-ADA collateral UTxO.
- **Balancing over `cardano-tx-tools`** — a clean "balance this"
  entry point that drives the existing build/balance machinery with
  correct inputs and collateral.
- **UTxO reports** — pure-ADA vs token, fragmentation, *max collateral
  reachable*, fee/collateral headroom.

## Architecture

One pure `wallet-core`, two frontends:

- **Native operator CLI** (`resolve`, `utxo-report`,
  `select-collateral`, `consolidate` / `provision-collateral`,
  `balance`, `submit`) — n2c reads, optional age-vault signing.
- **Haskell → WASM** module consumed by a **PureScript + CIP-30**
  browser wallet (spago / esbuild / Halogen).

The core is pure and WASM-portable, so both frontends run the same
selection and verification code.

## Trust model

`TxIn -> TxOut` resolution is a pluggable backend, tiered by trust:

| Backend | Trust | Mechanism |
|---|---|---|
| N2C (own node) | trusted | `LocalStateQuery`, authoritative |
| Blockfrost / Koios | untrusted → **verified** | fetch producing-tx CBOR, recompute `blake2b-256(body)`, assert `== txid`, read `outputs[ix]` |

The verifier `TxIn -> TxCbor -> Either ResolveError TxOut` is **pure**
and lives in the core, so the browser inherits the guarantee. CIP-30
`getUtxos` provides the user's own (trusted) wallet UTxOs; any other
`TxIn` is resolved through a verified Blockfrost/Koios fetch.

Protocol parameters are **best-effort** from the backend: a wrong value
only mis-sizes fee/collateral and the node re-validates at submit, so
funds cannot be stolen. This weaker guarantee is documented, not hidden.

## Collateral selection algorithm

Inside the fee fixpoint (so the required amount is known each pass):

1. `required = ceil(fee × ppCollateralPercentage / 100)`.
2. Candidates: VKey-locked UTxOs. Pure-ADA preferred; native-asset
   UTxOs allowed when `collateral_return` is built to conserve their
   assets.
3. Largest-first, reusing inputs already in the body, until
   `sum ≥ required` or `count = maxCollateralInputs`.
4. Exhausted and still short → `CollateralShortfall { selected, sum,
   required }` — never a silent under-provision.

The leftover (`sum − total_collateral`) becomes `collateral_return`,
carrying any collateral-input assets; folded into `total_collateral`
only when an asset-free residual is below min-UTxO.

Why `getCollateral` (CIP-30) is bypassed: it exposes only a handful of
small pre-set collateral UTxOs — precisely the limitation this project
removes. The browser reads `getUtxos` and runs our selection instead.

## Coin selection

Pluggable strategy: `LargestFirst` (default — fewest inputs, matches
the collateral cap reasoning) and `RandomImprove` (CIP-2, opt-in,
seeded so WASM stays deterministic).

## Submission & signing

- **Submit** symmetric across N2C / Blockfrost / Koios / CIP-30, with
  confirm-on-chain (poll for the txid or time out).
- **Signing**: build-only by default. Browser → CIP-30 `signTx` /
  `submitTx`. CLI → optional age-vault signing. No multisig in v1;
  co-signing is handed off to `cardano-tx-tools` / amaru.

## Package layout (target)

```
lib/   wallet-core   pure: selection, collateral, resolution verifier, reports (WASM-safe)
lib/   wallet-tx     balancing/assembly over cardano-tx-tools
app/   wallet-cli    native operator CLI (n2c reads, vault signing)
wasm/  wallet-wasm   foreign-export surface for the browser
web/   purescript CIP-30 wallet (spago + esbuild + Halogen)
lean/  selection invariants (optional formalization)
```

v0 ships `wallet-core` with the pure selection algorithms only; the
remaining components land as tracked tickets, each admitting its
dependencies against the WASM-portability rule first.
