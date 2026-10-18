# Tasks: Vault v1 (issue #19)

## Slice vault-v1

- [ ] passphrase-intake-tty-and-fd — `Vault.Passphrase` ported; `--passphrase-fd` replaces `--passphrase-file`.
- [ ] v1-payload-and-tx-sign-reader — `Vault.Payload` with v1 encoder and v1 + tx-sign reader, identity selector.
- [ ] scrypt-seal-open-with-cap — `Vault.Scrypt` seal at given factor, open refuses above cap; opaque vault API removed.
- [ ] exclusive-vault-file — `Vault.File` exclusive 0600 no-follow create, removal on failed write.
- [ ] cwt-vault-commands — `cwt vault seal` emits v1 via `runVaultSeal`; `cwt sign --signing-key-vault` reads v1 and tx-sign.
- [ ] fixtures-with-provenance — cardano-cli key pair and tx-sign vault fixtures with recorded commands.
- [ ] age-in-test-environment — stock `age` in dev shell, hosted unit-tests app and `checks.unit`.
- [ ] ported-vault-spec — singular VaultSpec and passphrase cases ported under `vault v1`, plus acceptance examples.
