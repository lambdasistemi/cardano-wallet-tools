# Tasks: Vault v1 (issue #19)

## Slice vault-v1

- [X] passphrase-intake-tty-and-fd — `Vault.Passphrase` ported; `--passphrase-fd` replaces `--passphrase-file`.
- [X] v1-payload-and-tx-sign-reader — `Vault.Payload` with v1 encoder and v1 + tx-sign reader, identity selector.
- [X] scrypt-seal-open-with-cap — `Vault.Scrypt` seal at given factor, open refuses above cap; opaque vault API removed.
- [X] exclusive-vault-file — `Vault.File` exclusive 0600 no-follow create, removal on failed write.
- [X] cwt-vault-commands — `cwt vault seal` emits v1 via `runVaultSeal`; `cwt sign --signing-key-vault` reads v1 and tx-sign.
- [X] fixtures-with-provenance — cardano-cli key pair and tx-sign vault fixtures with recorded commands.
- [X] age-in-test-environment — stock `age` in dev shell, hosted unit-tests app and `checks.unit`.
- [X] ported-vault-spec — singular VaultSpec and passphrase cases ported under `vault v1`, plus acceptance examples.

## Slice tx-sign-correction

- [X] addr-xsk-tx-sign-source — tx-sign `cardano-addresses-addr-xsk` identities open to an extended key that signs; witness verifies under its vkey.
- [X] tx-sign-key-hash-check — opening a tx-sign identity refuses a stored `keyHash` that is not blake2b-224 of its vkey.
- [X] witness-over-body-hash — every `cwt` witness signs blake2b-256 of the body, equal to the `cardano-cli` witness for the same key and body.
