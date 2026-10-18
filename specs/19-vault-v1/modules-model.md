# Modules model: Vault v1

Dependency direction: `Cli.Vault → Vault.Scrypt → Vault.Payload`,
`Cli.Vault → Vault.File`, `Cli.Vault → Vault.Passphrase`,
`Vault.Scrypt → Vault.Passphrase`. Nothing in `Vault.*` imports
`Cli.*`. All under `lib/`, all ledger-free.

| module | responsibility | replaces |
|---|---|---|
| `Cardano.Wallet.Tools.Vault.Payload` | vault-kind-neutral plaintext: the payment signing key value, the v1 `cardano-cli` envelope encoder, the reader for v1 envelope and tx-sign JSON payload (with identity selector), key → `Signer` | envelope parsing in `Cli.Vault` |
| `Cardano.Wallet.Tools.Vault.Scrypt` | the passphrase (scrypt) vault kind: cap, seal with given work factor, open bounded by cap, the opening refusal | `Cardano.Wallet.Tools.Vault` opaque API |
| `Cardano.Wallet.Tools.Vault.File` | exclusive 0600 no-follow creation bracket with removal on failed write | `BS.writeFile` in `app/Main.hs` |
| `Cardano.Wallet.Tools.Vault.Passphrase` | opaque passphrase, tty (echo-off) and fd sources, confirmation rule, refusals | `promptPassphrase`/`readPassphrase`/`PassphraseFile` |
| `Cardano.Wallet.Tools.Cli.Vault` | optparse surface (`--signing-key`, `--signing-key-vault`, `--passphrase-fd`, `--vault-identity`, `--work-factor`, `--out`) and the command handlers `cwt` runs; `app/Main.hs` only parses and dispatches | current module, minus `--passphrase-file` |

`Cardano.Wallet.Tools.Vault` (the old module) is deleted, or kept only
as a re-export of the four `Vault.*` modules; the commit owner decides,
and the PR Contract heading lists whichever exists.

A second vault kind (FIDO2, #21) is a sibling `Vault.<Kind>` module
reusing `Vault.Payload` and `Vault.File`; age forbids mixing scrypt
with other recipients, so a kind is a whole file, never a recipient.

Data rows: `data-model.md`. Signatures: `functions-model.md`.
