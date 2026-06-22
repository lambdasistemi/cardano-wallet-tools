# cardano-wallet-tools

Operator wallet-UTxO toolkit and a PureScript CIP-30 browser wallet,
built over one pure Haskell core.

- **[Design](design.md)** — architecture, trust model, and the
  collateral-selection algorithm.
- **Constitution** — the authoritative architectural decisions live in
  `.specify/memory/constitution.md`.

## What it owns

- Trust-minimized UTxO resolution (N2C trusted; Blockfrost/Koios
  verified via producing-tx CBOR + `blake2b-256(body) == txid`).
- Coin and **collateral** selection — multi-UTxO, native-asset-aware,
  respecting `maxCollateralInputs`, with honest shortfall reporting.
- Wallet consolidation and fat-collateral provisioning.
- Balancing over [`cardano-tx-tools`](https://github.com/lambdasistemi/cardano-tx-tools).
- UTxO reports: pure-ADA vs token, fragmentation, max collateral
  reachable.
