# Functions model: FIDO2 vault

New exported signatures. Argument names are binding; exact Haskell
spelling of auxiliary types is the commit owner's. Every refusal type
has a `render… :: refusal -> Text`.

## `Vault.Plugin`
- `parsePluginRecipient :: text:Text -> Maybe PluginRecipient`
- `parsePluginIdentity :: text:Text -> Maybe PluginIdentity`
- `sealToPlugins :: ui:PluginUi -> recipients:NonEmpty PluginRecipient -> plaintext:ByteString -> IO (Either PluginRefusal ByteString)` — effects: file key and nonce entropy, plugin processes
- `openWithPlugins :: ui:PluginUi -> identities:NonEmpty PluginIdentity -> ageFile:ByteString -> IO (Either PluginRefusal ByteString)` — effects: plugin processes

## `Vault.Fido2`
- `parseFido2Recipient :: text:Text -> Either Fido2Refusal Fido2Recipient`
- `parseFido2Identities :: identityFile:ByteString -> Either Fido2Refusal (NonEmpty Fido2Identity)`
- `sealFido2Vault :: ui:PluginUi -> recipients:NonEmpty Fido2Recipient -> key:PaymentSigningKey -> IO (Either Fido2Refusal ByteString)`
- `openFido2Vault :: ui:PluginUi -> identities:NonEmpty Fido2Identity -> vaultBytes:ByteString -> IO (Either Fido2Refusal OpenedKey)`
- `rekeyFido2Vault :: ui:PluginUi -> identities:NonEmpty Fido2Identity -> recipients:NonEmpty Fido2Recipient -> vaultBytes:ByteString -> IO (Either Fido2Refusal ByteString)` — returns new vault bytes holding the same key; writes nothing

## `Cli.Fido2`
- `terminalPluginUi :: PluginUi` — stderr messages, `/dev/tty` hidden-echo secrets
- `vaultCreateParser :: Parser VaultCreateOptions` — `--fido2`, `--recipient R` (repeatable, ≥ 1), `--signing-key FILE`, `--out FILE`
- `runVaultCreate :: ui:PluginUi -> options:VaultCreateOptions -> IO (Either Text ())`
- `vaultRekeyParser :: Parser VaultRekeyOptions` — `--vault FILE`, `--fido2-identity FILE`, `--recipient R` (≥ 1), `--out FILE`
- `runVaultRekey :: ui:PluginUi -> options:VaultRekeyOptions -> IO (Either Text ())`
- `fido2KeySourceParser :: Parser Fido2KeySource` — `--fido2-vault FILE --fido2-identity FILE`
- `loadSignerFromFido2 :: ui:PluginUi -> source:Fido2KeySource -> IO (Either Text (Signer IO))`

## `app/Main.hs`
- `vault create` and `vault rekey` subcommands; `sign` accepts
  `Fido2KeySource` as an alternative to `SigningKeySource`.

Removed: nothing.
