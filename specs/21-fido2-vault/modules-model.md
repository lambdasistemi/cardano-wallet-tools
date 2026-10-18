# Modules model: FIDO2 vault

Dependency direction (new edges only):
`Cli.Fido2 → Vault.Fido2 → Vault.Plugin`,
`Vault.Fido2 → Vault.Payload`, `Cli.Fido2 → Vault.File`,
`Cli.Fido2 → Vault.Passphrase` (hidden-echo terminal reads only),
`app/Main.hs → Cli.Fido2`. `Vault.Plugin` imports no `Vault.*` kind
module and nothing ledger-typed; nothing in `Vault.*` imports `Cli.*`.

| module | responsibility |
|---|---|
| `Cardano.Wallet.Tools.Vault.Plugin` | kind-neutral age plugin client: resolve the plugin binary from a recipient/identity, run the recipient-v1 and identity-v1 phases over stdio, relay plugin interaction through a caller-supplied UI, and seal/open a binary age v1 file whose stanzas come from plugins |
| `Cardano.Wallet.Tools.Vault.Fido2` | the FIDO2 vault kind: `fido2-hmac` recipients and identities (parse, refuse other kinds), seal a v1 payload to a non-empty recipient set, open with one identity, rekey to a new set |
| `Cardano.Wallet.Tools.Cli.Fido2` | optparse surface and handlers for `cwt vault create --fido2`, `cwt vault rekey`, and the `cwt sign --fido2-vault/--fido2-identity` key source; the terminal-backed plugin UI |
| fake plugin (test-only executable, name the commit owner's) | a plugin speaking the real stdio protocol for the `fido2-hmac` name, with recipient-isolated wrapping and steerable interaction; never installed as `age-plugin-fido2-hmac` by the package |

Internal helper modules under `Vault.Plugin` are the commit owner's;
the PR Contract lists every exposed module.

Unchanged: `Vault.Payload`, `Vault.Scrypt`, `Vault.File`,
`Vault.Passphrase`, `Cli.Vault`.

Data rows: `data-model.md`. Signatures: `functions-model.md`.
