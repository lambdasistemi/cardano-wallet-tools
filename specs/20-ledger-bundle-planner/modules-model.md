# Modules model (#20)

New public sublibrary `ledger` of package `cardano-wallet-tools`
(`visibility: public`, consumed as `cardano-wallet-tools:ledger`), source
dir `ledger/`. Depends on the core library, `cardano-ledger-*`, cardano
crypto/binary packages; never on `cardano-tx-tools`.

Dependency direction:
`Ledger.Cli.Bundle → Ledger.Bundle → Ledger.Envelope → core Sign.Witness`;
`Ledger.Submit → Ledger.Bundle`; `Ledger.Witness → Ledger.Envelope`.
Nothing in the core library imports `Ledger.*`.

| module | responsibility | ported from |
|---|---|---|
| `Cardano.Wallet.Tools.Ledger.Envelope` | text envelope value and JSON; unsigned-transaction envelope encode/decode (written and accepted type labels); detached-witness envelope encode/decode over the core `DetachedWitness` | `Bundle.hs` envelope half |
| `Cardano.Wallet.Tools.Ledger.Bundle` | bundle v1 types, JSON codec, body identity and deadline, refusals and their rendering, offline checks (all refusals and first refusal) | `Bundle.hs` |
| `Cardano.Wallet.Tools.Ledger.Witness` | ledger-typed detached-witness signer over the body hash; assembling a transaction with exactly a given witness set | `Signing.hs` minus the `SignedTx` capability |
| `Cardano.Wallet.Tools.Ledger.Submit` | chain-view types, needed keys, witness pairing by signature, the ordered plan, submit refusals | `Submit.hs` + `ChainPoint`/`InclusionStatus` |
| `Cardano.Wallet.Tools.Ledger.Cli.Bundle` | optparse surface and runner of `cwt bundle check`; `app/Main.hs` only parses and dispatches | new |

Promotion: `DetachedWitness` is the core
`Cardano.Wallet.Tools.Sign.DetachedWitness`; no second witness type is
declared. Singular's `SignedTx` newtype stays in singular.

Data rows: `data-model.md`. Signatures: `functions-model.md`.
