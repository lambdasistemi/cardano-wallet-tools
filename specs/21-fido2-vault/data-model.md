# Data model: FIDO2 vault

| abstraction | module | fields / constructors | invariants |
|---|---|---|---|
| `PluginRecipient` | `Vault.Plugin` | the recipient text and the plugin name derived from it | name from the bech32 HRP `age1<name>` as age does; parse refuses anything else |
| `PluginIdentity` | `Vault.Plugin` | the identity text and the plugin name derived from it | name from `AGE-PLUGIN-<NAME>-` as age does; `Show` hides the identity text |
| `PluginUi` | `Vault.Plugin` | show a message; request a public value (prompt); request a secret (prompt); confirm (prompt, yes, optional no) | the client calls only these for plugin interaction; a secret is returned to the plugin and never kept |
| `PluginRefusal` | `Vault.Plugin` | binary not found (binary name); plugin error (plugin's message, no secrets); protocol violation (what); no stanza unwrapped | carries no file key, secret or key bytes |
| `Fido2Recipient` | `Vault.Fido2` | a `PluginRecipient` whose name is `fido2-hmac` | non-empty set on seal and rekey; duplicates are one recipient |
| `Fido2Identity` | `Vault.Fido2` | a `PluginIdentity` whose name is `fido2-hmac`, read from an identity file (one or more lines; comments and blanks ignored as age does) | `Show` hides it |
| `Fido2Refusal` | `Vault.Fido2` | not a fido2-hmac recipient (text); not a fido2-hmac identity; no recipients; plugin binary missing (binary name); vault refused (`VaultRefusal`) | renders without secrets; every open failure but a missing binary is vault refused `VaultNotOpened`; `VaultRefusal` itself is unchanged |

On-disk FIDO2 vault: binary age v1 file (`age-encryption.org/v1`), one
stanza per recipient as returned by the plugin (tag `fido2-hmac` for the
real plugin), header MAC over the file key, payload = vault v1 plaintext
(`encodeV1Payload`). No scrypt stanza.

Fake plugin state: its recipients and identities encode a per-key
secret the commit owner chooses; a stanza wrapped for recipient A does
not unwrap with identity B. Steering is by environment variables the
test sets (names the commit owner's).
