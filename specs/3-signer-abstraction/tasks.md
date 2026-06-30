# Tasks: Signer Abstraction And Detached Witness Attach Core

## Slice A - Signer Surface And Witness CBOR

- [X] T001-SA Create `lib/Cardano/Wallet/Tools/Sign.hs` with the
      `Signer` record-of-functions and key-free body/witness surface.
- [X] T002-SA Create `lib/Cardano/Wallet/Tools/Sign/Witness.hs` with
      detached witness types plus raw and Shelley-envelope CBOR
      encoders/decoders.
- [X] T003-SA Add focused witness golden and round-trip tests under
      `test/`.
- [X] T004-SA Update `cardano-wallet-tools.cabal` for new modules,
      tests, and minimal pure dependencies.
- [X] T005-SA Run `./gate.sh` and commit with
      `Tasks: T001, T002, T003, T004, T005`.

## Slice B - Body-Preserving Witness Attachment

- [X] T006-SB Create
      `lib/Cardano/Wallet/Tools/Sign/AttachWitness.hs` with
      `transactionBodyBytes` and `attachWitnesses`.
- [X] T007-SB Splice vkey witnesses into witness-set map key `0`
      while preserving the original transaction body bytes.
- [X] T008-SB Add focused tests proving witness insertion and body-byte
      preservation after attachment.
- [X] T009-SB Update `cardano-wallet-tools.cabal` for the attachment
      module/test module if not already covered.
- [X] T010-SB Run `./gate.sh` and commit with
      `Tasks: T006, T007, T008, T009, T010`.

## Finalization

- [X] T011-F Run final `./gate.sh` at HEAD.
- [X] T012-F Audit/update the PR body.
- [X] T013-F Drop `gate.sh` in the ready-for-review commit and mark the
      PR ready.
