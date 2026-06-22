# cardano-wallet-tools

Operator wallet-UTxO toolkit and a PureScript CIP-30 browser wallet,
built over one pure Haskell core. It owns the wallet-side concerns that
general transaction tooling leaves out — **trust-minimized UTxO
resolution**, **coin and collateral selection**, **consolidation /
collateral provisioning**, **balancing**, and **UTxO reporting** —
while delegating Conway transaction assembly to
[`cardano-tx-tools`](https://github.com/lambdasistemi/cardano-tx-tools).

## Why

A script-heavy transaction needs collateral equal to `fee × 150%`.
Most tooling pins collateral to a single wallet UTxO, so a wallet full
of small or token-bearing UTxOs fails to build even when it holds
ample funds. `cardano-wallet-tools` makes selection a first-class,
verifiable concern: multi-UTxO, native-asset-aware collateral with a
correct `collateral_return`, respecting `maxCollateralInputs`, with
honest shortfall reporting.

## Architecture

```
        wallet-core (pure, WASM-safe)
        selection · collateral · resolution verifier · reports
                 │                         │
        native operator CLI        Haskell → WASM
                                          │
                              PureScript CIP-30 browser wallet
```

- **N2C is trusted; Blockfrost/Koios are verified** — every third-party
  `TxOut` is backed by the producing transaction's CBOR with a checked
  `blake2b-256(body) == txid`. The verifier is pure, so the browser
  gets the same guarantee.
- **Build-only by default** — the core never holds keys. The browser
  signs via CIP-30; the CLI can optionally sign via an age vault.

See [`docs/design.md`](docs/design.md) and the project
[constitution](.specify/memory/constitution.md).

## Development

Everything runs inside the Nix dev shell:

```bash
nix develop
just build          # cabal build (-O0)
just unit           # run the test suite
just format-check   # fourmolu --mode check
just hlint          # hlint
just ci             # full local CI mirror
```

## Status

v0 scaffold: the pure `wallet-core` selection algorithms (collateral +
strategy). The `cardano-tx-tools`/ledger wiring, WASM target, operator
CLI, and PureScript CIP-30 wallet land as tracked follow-up tickets.

## License

Apache-2.0.
