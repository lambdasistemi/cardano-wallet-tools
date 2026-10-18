# Data model: Vault v1

| abstraction | module | fields / constructors | invariants |
|---|---|---|---|
| `PaymentSigningKey` | `Vault.Payload` | opaque, one Ed25519 secret key (32 bytes) | no `Show` revealing key bytes |
| `VaultPayloadRefusal` | `Vault.Payload` | not a signing-key envelope; tx-sign identity missing (selector, available labels); tx-sign source kind unsupported (kind) | carries no key bytes |
| `IdentitySelector` | `Vault.Payload` | a tx-sign identity label (text) | absent ⇒ exactly one identity required |
| `VaultRefusal` | `Vault.Scrypt` / `Vault.File` | path exists (path); not written (path); not opened | `not opened` is the single opening refusal for every open failure; no passphrase or key bytes |
| work-factor cap | `Vault.Scrypt` | `WorkFactor` 18 | seal accepts 1..18 from the CLI; open refuses > 18 |
| `Passphrase` | `Vault.Passphrase` | opaque non-empty bytes | `Show` prints a fixed marker; equality by content |
| `PassphraseSource` | `Vault.Passphrase` | terminal; descriptor (fd number) | no path, env or argument constructor |
| `Confirmation` | `Vault.Passphrase` | ask once; ask twice | descriptor reads once regardless |
| `PassphraseRefusal` | `Vault.Passphrase` | empty; confirmation differs; descriptor unreadable (fd); terminal unavailable | no passphrase bytes |

On-disk v1: binary age v1 file, one `scrypt` stanza, plaintext =
`{"type":"PaymentSigningKeyShelley_ed25519","description":…,"cborHex":"5820<64 hex>"}`.

Accepted-on-read tx-sign payload (cardano-tx-tools `1b623b1`):
`{"cardanoTxSignVault":{"version":1,"identities":{<label>:{"label","network","keyHash","description"?,"source":{"kind":"cardano-cli-skey","keyEnvelope":<envelope object>}}}}}`;
version ≠ 1 and map-key/label mismatch are refused as not-a-signing-key payloads.
