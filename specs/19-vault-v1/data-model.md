# Data model: Vault v1

| abstraction | module | fields / constructors | invariants |
|---|---|---|---|
| `PaymentSigningKey` | `Vault.Payload` | opaque, one Ed25519 secret key (32 bytes, cardano-cli); the only key the writer takes | no `Show` revealing key bytes |
| `ExtendedSigningKey` | `Vault.Payload` | opaque extended BIP32-Ed25519 key (kL‖kR 64 bytes, 32-byte chain code) from a tx-sign `addr_xsk` source; read only, never written | no `Show` revealing key bytes |
| `OpenedKey` | `Vault.Payload` | `OpenedPlain PaymentSigningKey` \| `OpenedExtended ExtendedSigningKey`; what opening a vault yields | both forms sign blake2b-256 of the body |
| `VaultPayloadRefusal` | `Vault.Payload` | not a signing-key envelope; tx-sign identity missing (selector, available labels); tx-sign source kind unsupported (kind); tx-sign key hash mismatch (label) | carries no key bytes; `openVault` passes all but the first through `VaultPayloadRefused` |
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
`{"cardanoTxSignVault":{"version":1,"identities":{<label>:{"label","network","keyHash","description"?,"source":{"kind":"cardano-cli-skey","keyEnvelope":<envelope object>} | {"kind":"cardano-addresses-addr-xsk","bech32":"addr_xsk1…"}}}}}`;
version ≠ 1 and map-key/label mismatch are refused as not-a-signing-key payloads.
`keyHash` is checked: blake2b-224 of the identity's verification key must equal it.
