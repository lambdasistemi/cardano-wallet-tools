# Functions model: Vault v1

New or changed exported signatures. Argument names are binding;
exact Haskell spelling of auxiliary types is the commit owner's.

## `Vault.Payload`
- `encodeV1Payload :: key:PaymentSigningKey -> ByteString`
- `decodeVaultPayload :: selector:Maybe IdentitySelector -> plaintext:ByteString -> Either VaultPayloadRefusal PaymentSigningKey`
- `parseSigningKeyEnvelope :: envelope:ByteString -> Either VaultPayloadRefusal PaymentSigningKey`
- `signerFromKey :: key:PaymentSigningKey -> Signer m` (Applicative m) — signs blake2b-256 of the body bytes it is given, with the key's Ed25519 or extended Ed25519 signing rule

## `Vault.Scrypt`
- `vaultWorkFactorCap :: WorkFactor`
- `sealVault :: workFactor:WorkFactor -> passphrase:Passphrase -> key:PaymentSigningKey -> IO (Either VaultRefusal ByteString)` — effect: salt entropy only
- `openVault :: selector:Maybe IdentitySelector -> passphrase:Passphrase -> vaultBytes:ByteString -> Either VaultRefusal PaymentSigningKey` — pure

## `Vault.File`
- `withVaultFile :: path:FilePath -> write:(Handle -> IO a) -> IO (Either VaultRefusal a)`
- `createVaultFile :: path:FilePath -> bytes:ByteString -> IO (Either VaultRefusal ())`

## `Vault.Passphrase`
- `mkPassphrase :: raw:ByteString -> Either PassphraseRefusal Passphrase`
- `passphraseBytes :: passphrase:Passphrase -> ByteString`
- `confirmPassphrase :: first:ByteString -> second:ByteString -> Either PassphraseRefusal Passphrase`
- `readPassphrase :: confirmation:Confirmation -> source:PassphraseSource -> IO (Either PassphraseRefusal Passphrase)`
- `withHiddenEcho :: fd:Fd -> action:IO a -> IO a`
- `renderPassphraseRefusal`, `renderVaultRefusal`, `renderVaultPayloadRefusal :: refusal -> Text`

## `Cli.Vault`
- `signingKeySourceParser :: Parser SigningKeySource` — vault form carries path, `PassphraseSource`, `Maybe IdentitySelector`
- `vaultSealParser :: Parser VaultSealOptions` — key path, out path, `PassphraseSource`, work factor (default cap, 1..cap)
- `runVaultSeal :: options:VaultSealOptions -> IO (Either Text ())`
- `loadSignerFromSource :: source:SigningKeySource -> IO (Either Text (Signer IO))`

Removed: `encryptVault`, `decryptVault`, `mkVaultPassphrase`,
`VaultPassphrase`, `defaultWorkFactor`, `promptPassphrase`,
`PassphraseFile`, `loadSignerFromFile`'s die-on-error path.
