# Spec: Vault v1 (issue #19)

Class: **changes behaviour** (key custody, file creation, secret intake).
Topology: OWNER (commit owner + persistent commit auditor).

## User stories

- **Seal a key a stock toolchain can open.** An operator runs
  `cwt vault seal --signing-key payment.skey --out payment.age` and gets
  one binary age file whose plaintext is a `cardano-cli` payment
  signing-key text envelope. `age -d payment.age` with the passphrase
  yields that envelope with no Lambdasistemi code involved.
- **Sign with a vault.** `cwt sign --signing-key-vault payment.age`
  opens the vault and attaches the key's witness, reading the
  passphrase from `/dev/tty` (echo off) or from `--passphrase-fd N`.
- **Keep existing tx-sign vaults usable.** A vault written by
  cardano-tx-tools `tx-sign vault` (JSON identity payload) opens and
  signs with `cwt`.

## Requirements and invariants

Each name is stable; tests and the gate refer to these names.

| invariant | holds when | fails when |
|---|---|---|
| `v1-plaintext-is-cardano-cli-envelope` | decrypting a sealed vault with stock `age -d` yields a JSON text envelope of type `PaymentSigningKeyShelley_ed25519` whose `cborHex` is `5820` + the 32 key bytes of the sealed key | plaintext is anything else (opaque bytes, JSON wrapper, other key type) |
| `v1-single-scrypt-stanza` | the vault is a binary (not armored) age file with exactly one scrypt recipient | armored output, extra recipients |
| `seal-uses-given-work-factor` | the scrypt stanza records exactly the work factor passed to seal | a constant replaces the argument |
| `open-refuses-above-cap` | opening a vault whose scrypt work factor exceeds the cap (18) is refused with the opening refusal, for every opening path (v1 and tx-sign payload) | any vault above the cap opens |
| `open-refusal-is-uniform` | wrong passphrase, corrupt file, non-vault, above-cap and non-key plaintext answer one refusal that names no cause-specific secret | the refusal distinguishes passphrase from corruption, or carries key/passphrase bytes |
| `exclusive-0600-create` | the vault file is created with `O_EXCL`, mode 0600, never following a symlink | an existing file or symlink is overwritten or followed |
| `existing-path-untouched` | an existing path (regular file or symlink) is refused and its bytes / its target are unchanged | any byte of an existing path or symlink target changes |
| `failed-write-removes-file` | a write that fails after creation removes the file that call made, and only that file | a partial file remains |
| `reader-accepts-tx-sign-payload` | a plaintext `{"cardanoTxSignVault":{"version":1,"identities":{…}}}` with a `cardano-cli-skey` source opens to that key; the identity is chosen by label when a selector is given, else the single identity; several identities and no selector is refused naming the labels | a valid tx-sign vault does not open, or opens a key other than the selected identity's |
| `writer-emits-only-v1` | every vault `cwt` writes has the v1 plaintext; no code path writes the tx-sign JSON | a tx-sign payload can be written |
| `passphrase-sources-tty-or-fd-only` | the passphrase is read from `/dev/tty` (echo off, restored on every exit) or from an inherited fd (`--passphrase-fd N`, one line, line ending trimmed, never a confirmation); no argument, environment variable or path supplies it | `--passphrase-file` or any path/env/argument source exists |
| `tty-creation-confirms` | a terminal source asks twice on seal and refuses a mismatch; an fd source never asks twice | seal from tty accepts one unconfirmed line, or fd reads twice |
| `empty-passphrase-refused` | an empty passphrase (after trimming the line ending) is refused before any crypto | an empty passphrase seals or opens |
| `passphrase-never-rendered` | `Show` of a passphrase prints a fixed marker; no refusal or rendered error contains passphrase bytes | passphrase bytes appear in any `show`/render output |
| `seal-input-must-be-signing-key` | seal refuses an input that is not a supported payment signing-key envelope, before creating the output file | a non-key input is sealed or leaves an output file |
| `reader-accepts-addr-xsk-source` | a tx-sign identity whose source is `cardano-addresses-addr-xsk` (bech32 `addr_xsk`, 96 bytes: extended secret kL‖kR then chain code) opens to that extended key, and its witness verifies under the key's verification key | an `addr_xsk` identity is refused, or yields a witness that does not verify |
| `tx-sign-key-hash-checked` | opening a tx-sign identity computes blake2b-224 of its verification key and refuses the identity when it differs from the stored `keyHash`; the refusal carries no key material | a mismatched identity opens, or the refusal names key bytes |
| `witness-signs-body-hash` | every witness `cwt` produces (plain key, v1 vault, tx-sign `cardano-cli-skey`, tx-sign `addr_xsk`) is an Ed25519 signature over blake2b-256 of the transaction body bytes, equal to the witness `cardano-cli` produces for the same key and body | the signature is over the raw body or any other message |
| `core-stays-ledger-free` | the library's build-depends gain no `cardano-ledger-*`, `cardano-api` or `cardano-crypto-class` package | such a dependency appears |

## Rejections (observable, one line on stderr, exit 1, no secret)

vault path exists · vault not written · vault not opened ·
passphrase empty · confirmation differs · descriptor N unreadable ·
terminal unavailable · tx-sign identity missing (lists labels) ·
unsupported tx-sign source kind · tx-sign key hash mismatch (names the label) ·
seal input is not a signing key ·
work factor out of range.

## Acceptance (issue #19, authoritative)

1. A vault written by `cwt` decrypts with stock `age -d` and yields a
   valid `cardano-cli` signing-key envelope.
2. A fixture vault in `tx-sign vault` JSON format opens and signs, for both source kinds: `cardano-cli-skey` and `cardano-addresses-addr-xsk`.
3. A `tx-sign vault` identity whose stored key hash does not match its key is refused.
4. A vault above the work-factor cap is refused.
5. The ported singular `VaultSpec` and passphrase cases pass in this
   repo's `just ci`.

Stock `cardano-cli` is not available in CI. Substitute for line 1's
"valid envelope": a committed fixture pair (`.skey`, `.vkey`) produced
by a real `cardano-cli address key-gen`, with the command recorded
beside it; the test seals that `.skey`, decrypts with stock `age -d`,
parses the plaintext as a `cardano-cli` envelope, and requires the
derived verification key to equal the fixture `.vkey` key bytes.

## Non-goals

FIDO2 vault kind (#21); key generation (`vault create`); extended
(bip32) keys in a v1 vault or as `--signing-key` (only tx-sign `addr_xsk`
sources are read); writing any extended key.

## Correction (epic ruling 2026-10-18, operator option A)

Acceptance lines 2 and 3 replace the first submission's limits on tx-sign
`addr_xsk` sources and the stored key hash. `witness-signs-body-hash` is a
defect found while preparing the correction: on the cardano-tx-tools
golden transaction `cwt sign` produced the same verification key as
`cardano-cli` but a different signature, because it signed the raw body.
