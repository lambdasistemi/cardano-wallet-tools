# Feature Specification: Signer Abstraction And Detached Witness Attach Core

## Issue

- GitHub: lambdasistemi/cardano-wallet-tools#3
- Parent epic: lambdasistemi/cardano-wallet-tools#4
- PR branch: `feat/3-signer-abstraction`

## P1 User Story

As a wallet-tools integrator, I can depend on a key-free signing boundary
that asks a backend for one detached vkey witness, then attaches that
witness to an unsigned transaction without changing the transaction body
bytes. The transaction id therefore stays stable before and after
attachment.

## User Stories

- As a backend author, I implement a `Signer` record-of-functions rather
  than a typeclass, so age-vault, CIP-30, and hardware signers can share
  the same boundary without forcing one inheritance model.
- As a browser/WASM integrator, I can use the shared witness and attach
  code without IO, clocks, randomness, keys, or native-only dependencies.
- As a transaction-building caller, I can attach either the raw ledger
  vkey witness form `[vkey, sig]` or the cardano-cli Shelley envelope
  form `[0, [vkey, sig]]`.
- As a wallet operator, I can trust that attaching a witness does not
  re-encode the transaction body and cannot accidentally change the txid.

## Functional Requirements

- FR-001: Expose `Cardano.Wallet.Tools.Sign` with a `Signer` record of
  functions. The record must be parameterized over the backend effect and
  must not require keys in the pure core.
- FR-002: Define transaction body bytes and detached witness types in the
  signing surface so concrete backends only exchange opaque bytes and a
  detached vkey witness.
- FR-003: Expose `Cardano.Wallet.Tools.Sign.Witness` with a detached
  witness type that decodes raw `[vkey, sig]` CBOR.
- FR-004: The witness decoder must also accept Shelley-envelope
  `[0, [vkey, sig]]` CBOR and reject other envelope tags.
- FR-005: The witness module must encode witnesses in raw and
  Shelley-envelope forms with golden round-trip tests.
- FR-006: Expose `Cardano.Wallet.Tools.Sign.AttachWitness` with
  `attachWitnesses` for CBOR transaction bytes.
- FR-007: `attachWitnesses` must splice detached witnesses into the
  transaction witness set at key `0` without re-encoding the transaction
  body term.
- FR-008: If a transaction already has vkey witnesses, attachment must
  preserve them and append/merge the new detached witnesses.
- FR-009: Non-vkey witness-set fields must be preserved byte-for-byte
  where possible by carrying their CBOR terms through unchanged.
- FR-010: Tests must prove the transaction body byte slice is identical
  before and after attachment.
- FR-011: The implementation must remain pure and deterministic: no IO,
  time, randomness, key handling, FFI, native process calls, or network.
- FR-012: `just ci` through the Nix dev shell must pass.

## Non-Goals

- Concrete signer backends: age vault, CIP-30, Ledger/Trezor, or
  cardano-cli wrappers.
- Key generation, key storage, key parsing, or signing-key validation.
- Multi-signer workflows, multisig, co-signing policy, or witness
  completeness validation.
- Ledger typed transaction decoding through cardano-ledger dependencies.

## Acceptance Criteria

- The library exposes `Cardano.Wallet.Tools.Sign`,
  `Cardano.Wallet.Tools.Sign.Witness`, and
  `Cardano.Wallet.Tools.Sign.AttachWitness`.
- The public signing boundary is a record-of-functions, not a typeclass.
- Witness CBOR tests cover both accepted forms and a rejected non-vkey
  envelope tag.
- Attachment tests show that body bytes are unchanged after adding one
  witness.
- The package builds and tests with `nix develop --quiet -c just ci`.

