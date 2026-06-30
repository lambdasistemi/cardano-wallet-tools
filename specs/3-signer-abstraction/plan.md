# Implementation Plan: Signer Abstraction And Detached Witness Attach Core

## Technical Shape

The package currently has only the pure selection modules and depends on
`base`, `containers`, and `text`. The implementation should keep the same
wallet-core posture: pure, WASM-portable, and free of cardano-ledger or
native-only dependencies. Add `bytestring` if needed for opaque CBOR bytes.

Do not touch `lib/Cardano/Wallet/Tools/Selection/` or `flake.nix`.

The reference implementation in `cardano-tx-tools` uses ledger types in:

- `/code/cardano-tx-tools/src/Cardano/Tx/Sign/Witness.hs`
- `/code/cardano-tx-tools/src/Cardano/Tx/Sign/AttachWitness.hs`

This ticket extracts the boundary and CBOR behavior, not the vault/key
logic. The driver should use the reference for wire shapes:

- raw vkey witness: `[vkey, sig]`
- Shelley/cardano-cli envelope: `[0, [vkey, sig]]`
- witness-set vkey entry: map key `0`

## Public Modules

`Cardano.Wallet.Tools.Sign`

- Export `Signer (..)`, `TxBodyBytes (..)`, and detached witness types.
- Keep the record effect-polymorphic, for example a function from
  `TxBodyBytes` to an effectful detached witness result.
- Re-export the witness and attach entry points that a backend user needs.

`Cardano.Wallet.Tools.Sign.Witness`

- Own `DetachedWitness`, decode errors, and raw/envelope encoders.
- Decode definite CBOR arrays for `[vkey, sig]` and `[0, [vkey, sig]]`.
- Treat `vkey` and `sig` as opaque byte strings. Do not validate keys.

`Cardano.Wallet.Tools.Sign.AttachWitness`

- Own `AttachWitnessError`, `transactionBodyBytes`, and `attachWitnesses`.
- Work on strict `ByteString` CBOR transaction bytes.
- Parse the top-level transaction array enough to identify the body term
  and witness-set term. Rebuild the transaction around the original body
  bytes, preserving the body term exactly.
- Parse witness-set maps enough to find key `0`. Preserve non-vkey map
  entries as original CBOR key/value terms.
- Encode the new key `0` value as a vkey witness collection that includes
  existing witness terms and newly encoded raw detached witnesses.

## CBOR Parser Guidance

Prefer a small local scanner over a broad dependency if that keeps the
package WASM-portable. The scanner only needs to split CBOR terms and
inspect simple headers:

- unsigned integer keys,
- byte strings,
- arrays,
- maps,
- tags,
- simple values,
- definite forms for all golden tests.

If indefinite terms are supported, test them. If not, return an explicit
unsupported-error and keep the behavior documented in Haddock.

## Slice Breakdown

### Slice A: Signer Surface And Witness CBOR

Create the signing facade and witness module. Add tests for witness
goldens and round trips. This slice can add `bytestring` to the package
manifest, but should avoid all ledger dependencies.

Expected commit subject:

`feat(sign): add signer boundary and detached witness cbor`

### Slice B: Body-Preserving Witness Attachment

Create the attachment module and tests. Add any remaining test modules to
the package manifest. Use property tests or generator-backed examples to
prove `transactionBodyBytes tx == transactionBodyBytes (attachWitnesses
wits tx)`.

Expected commit subject:

`feat(sign): attach witnesses without reencoding body`

## Verification

Every slice must run:

```sh
./gate.sh
```

The ticket is complete only after all tasks are checked, `./gate.sh`
passes at HEAD, the PR body reflects the delivered behavior, and the
PR-local `gate.sh` is removed in the final ready-for-review commit.

