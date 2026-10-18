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
[constitution](.specify/memory/constitution.md). The
[bundle v1](docs/bundle.md) file, its checks (`cwt bundle check`) and the
submit planner are in the `cardano-wallet-tools:ledger` sublibrary.

## FIDO2 vault

A signing key can be sealed to one or more FIDO2 authenticators instead of
a passphrase. The vault is a standard age file whose recipients are
`age1fido2-hmac1…` keys, wrapped by the `age-plugin-fido2-hmac` plugin:
the nix-built `cwt` brings the plugin, any other build needs it on the
`PATH`. The PIN and the touch are asked through the terminal.

```bash
# seal a key to two authenticators (repeat --recipient for each)
cwt vault create --fido2 \
  --recipient age1fido2-hmac1… --recipient age1fido2-hmac1… \
  --signing-key payment.skey --out payment.vault

# sign with whichever one is at hand; identity.txt holds its identity
cwt sign --fido2-vault payment.vault --fido2-identity identity.txt \
  < tx.cbor.hex > signed.cbor.hex

# lost one? open with a surviving identity, seal to the new set
cwt vault rekey --vault payment.vault --fido2-identity identity.txt \
  --recipient age1fido2-hmac1… --recipient age1fido2-hmac1… \
  --out renewed.vault
```

The output file must not exist and is written with mode 0600. `rekey`
never changes the old vault. Stock `age -d -i identity.txt payment.vault`
opens the same file.

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
