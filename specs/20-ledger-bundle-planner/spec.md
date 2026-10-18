# Spec: ledger layer — bundle v1, offline checks, submit planner (#20)

Class: **changes behaviour** (new library surface and a new `cwt`
command). Topology: OWNER (commit owner + persistent auditor).

## User stories

1. A tool that builds transactions (singular, cardano-tx-tools) hands an
   offline signer one bundle v1 file and depends on
   `cardano-wallet-tools:ledger` for its types, codec and checks instead of
   carrying its own copy.
2. An operator runs `cwt bundle check FILE` before signing and learns, with
   no network, whether the bundle is internally consistent; on failure the
   output names every failed check.
3. A submitting tool hands the planner the bundle, the detached witnesses,
   the resolved inputs, the chain's view and the tip, and receives an
   ordered send/skip plan or a refusal before anything is sent.
4. A reader of the docs site learns the bundle v1 format and how it maps
   one-to-one onto CIP-0103 `signTxs` / `submitTxs`.

## Requirements

- **ledger-sublibrary-isolation**: a public sublibrary `ledger` of the
  `cardano-wallet-tools` package depends on `cardano-ledger-*` (and the
  cardano crypto/binary packages) directly. It never depends on
  `cardano-tx-tools`. The core `library` stanza gains no ledger or cardano
  crypto dependency.
- **envelopes-cardano-cli-forms**: unsigned transactions are written as the
  `Unwitnessed Tx ConwayEra` text envelope of the complete Conway
  transaction, and `Tx ConwayEra` is also read. Detached witnesses are
  written and read as `TxWitness ConwayEra` / `Key Witness ShelleyEra`,
  byte-compatible with the official `cardano-cli` fixtures.
- **bundle-v1-schema**: JSON keys `version` (1), `command`, `networkMagic`,
  `stateToken`, `signers`, `transactions[]` with `identity`, `envelope`,
  `deadline`, `effects`. A bundle singular writes today decodes unchanged.
  `stateToken` is opaque and optional, set by the caller, never interpreted.
- **offline-checks**: recorded identity = body hash; recorded deadline =
  validity upper bound; identities distinct; every required signer key hash
  is the payment key hash of a listed signer address. One function reports
  every failed check, not only the first.
- **witness-paired-by-signature**: a witness belongs to the body its
  signature verifies over; file names play no part. A witness verifying
  against no body is refused.
- **needed-keys**: required signers ∪ payment key hashes of the outputs the
  inputs and collateral inputs spend; a script credential adds nothing; an
  input neither produced by an earlier body nor resolved is refused.
- **plan-refuses-before-send**: every refusal (foreign, unneeded, duplicate,
  missing witness; unresolved input; expired body) is raised before the plan
  holds any send step; bodies the chain holds become skip steps and are not
  judged.
- **cwt-bundle-check**: `cwt bundle check FILE` exits 0 printing only a
  summary when every check passes; otherwise exits non-zero and prints one
  line per failed check, naming it. An unreadable or undecodable file exits
  non-zero naming why.
- **signer-golden**: the ledger-typed detached-witness signer signs the
  body hash (blake2b-256 of the body bytes) and reproduces cardano-tx-tools
  `test/fixtures/tx-sign/witness.expected.hex` byte for byte.
- **bundle-docs-page**: a docs page specifies bundle v1 and its mapping onto
  CIP-0103 `signTxs`/`submitTxs` (ordered input, one witness set per index,
  all-or-nothing signing) and is in the MkDocs nav.

## Acceptance (issue #20, frozen)

1. The ported singular `BundleSpec` and `Registry/SubmitSpec` cases pass in
   `just ci` and in hosted CI.
2. The bundle spec page is published on the docs site.
3. `cwt bundle check FILE` runs the offline checks on a bundle v1 file:
   exit 0 with a summary when they pass, non-zero naming each failed check
   otherwise (tested in `just ci`).

## Non-goals

- Spec cases whose subject is singular-only code (its transaction builder,
  registry deployment, wallet derivation) are not ported; each dropped case
  is listed by name in the PR body with the reason.
- No `cwt bundle sign` / `cwt bundle submit`; no chain access.
- No change to vault modules (#21 owns FIDO2 in parallel).
