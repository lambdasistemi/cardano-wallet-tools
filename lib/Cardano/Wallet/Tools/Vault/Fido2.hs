{- |
Module      : Cardano.Wallet.Tools.Vault.Fido2
Description : The FIDO2 vault: an age file wrapped by fido2-hmac plugins
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A vault of this kind is one binary age v1 file whose every stanza was
wrapped by the @fido2-hmac@ plugin for one of its recipients, so any one
of the authenticators behind them opens it, and nothing else does. Its
plaintext is the vault v1 payload: the key's @cardano-cli@ text
envelope, exactly what the passphrase vault holds.

The plugin protocol, the plugin binary and the age framing are
'Cardano.Wallet.Tools.Vault.Plugin'\'s; this module is the kind: which
recipients and identities it takes, what it puts inside, and the one
refusal for every way a vault does not open.
-}
module Cardano.Wallet.Tools.Vault.Fido2
    ( -- * Recipients and identities
      Fido2Recipient
    , Fido2Identity
    , parseFido2Recipient
    , parseFido2Identities
    , fido2RecipientText

      -- * The vault
    , sealFido2Vault
    , openFido2Vault
    , rekeyFido2Vault

      -- * Refusals
    , Fido2Refusal (..)
    , renderFido2Refusal
    ) where

import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Payload
    ( OpenedKey
    , PaymentSigningKey
    , VaultPayloadRefusal (..)
    , decodeVaultPayload
    , encodeV1Payload
    )
import Cardano.Wallet.Tools.Vault.Plugin
    ( PluginIdentity
    , PluginRecipient
    , PluginRefusal (..)
    , PluginUi
    , openWithPlugins
    , parsePluginIdentity
    , parsePluginRecipient
    , pluginIdentityName
    , pluginRecipientName
    , pluginRecipientText
    , renderPluginRefusal
    , sealToPlugins
    )
import Data.ByteString (ByteString)
import Data.ByteString.Char8 qualified as BC
import Data.Char (isControl)
import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NE
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE

-- | A recipient of the @fido2-hmac@ plugin.
newtype Fido2Recipient = Fido2Recipient PluginRecipient
    deriving stock (Eq, Ord, Show)

-- | An identity of the @fido2-hmac@ plugin. It is never shown.
newtype Fido2Identity = Fido2Identity PluginIdentity
    deriving stock (Eq, Ord)

instance Show Fido2Identity where
    show _ = "<fido2 identity>"

-- | Why a FIDO2 vault operation was refused. None carries a secret.
data Fido2Refusal
    = -- | the text is not a @fido2-hmac@ recipient
      NotAFido2Recipient Text
    | -- | the identity file holds no @fido2-hmac@ identity, or a line that is not one
      NotAFido2Identity
    | -- | no recipient was given
      NoFido2Recipients
    | -- | the plugin binary is not on the PATH, naming it
      Fido2PluginMissing Text
    | -- | the plugin refused while wrapping, saying what it said
      Fido2PluginFailed Text
    | -- | the vault file operation was refused; 'VaultNotOpened' for every way a vault does not open
      Fido2VaultRefused VaultRefusal
    deriving stock (Eq, Show)

-- | The plugin name the kind is made of.
fido2Name :: Text
fido2Name = "fido2-hmac"

-- | The recipient text.
fido2RecipientText :: Fido2Recipient -> Text
fido2RecipientText (Fido2Recipient recipient) =
    pluginRecipientText recipient

-- | A @fido2-hmac@ recipient; any other text is refused.
parseFido2Recipient :: Text -> Either Fido2Refusal Fido2Recipient
parseFido2Recipient text = case parsePluginRecipient text of
    Just recipient
        | pluginRecipientName recipient == fido2Name ->
            Right (Fido2Recipient recipient)
    _ -> Left (NotAFido2Recipient text)

{- | The @fido2-hmac@ identities of an identity file: one per line,
blank lines and @#@ comments ignored as age ignores them. A file with no
identity, or with a line that is none, is refused.
-}
parseFido2Identities
    :: ByteString -> Either Fido2Refusal (NonEmpty Fido2Identity)
parseFido2Identities file = do
    identities <- traverse identity (filter meaningful (BC.lines file))
    maybe (Left NotAFido2Identity) Right (NE.nonEmpty identities)
  where
    meaningful line =
        let trimmed = BC.strip line
        in  not (BC.null trimmed) && BC.head trimmed /= '#'
    identity line = case TE.decodeUtf8' (BC.strip line) of
        Right text
            | Just parsed <- parsePluginIdentity text
            , pluginIdentityName parsed == fido2Name ->
                Right (Fido2Identity parsed)
        _ -> Left NotAFido2Identity

{- | Seal a signing key to the recipients, each counted once: the
vault bytes. Effects: the plugin processes.
-}
sealFido2Vault
    :: PluginUi
    -> NonEmpty Fido2Recipient
    -> PaymentSigningKey
    -> IO (Either Fido2Refusal ByteString)
sealFido2Vault ui recipients key =
    sealPlaintext ui recipients (encodeV1Payload key)

sealPlaintext
    :: PluginUi
    -> NonEmpty Fido2Recipient
    -> ByteString
    -> IO (Either Fido2Refusal ByteString)
sealPlaintext ui recipients plaintext =
    either (Left . sealRefusal) Right
        <$> sealToPlugins
            ui
            (plugin <$> NE.nub recipients)
            plaintext
  where
    plugin (Fido2Recipient recipient) = recipient

{- | Open vault bytes with the identities, any one of which may be the
vault's. Wrong identity, corrupt file, a vault of another kind, a plugin
error and a plaintext that is not a key all answer 'VaultNotOpened'; a
plugin binary that is not installed is its own refusal. Effects: the
plugin processes.
-}
openFido2Vault
    :: PluginUi
    -> NonEmpty Fido2Identity
    -> ByteString
    -> IO (Either Fido2Refusal OpenedKey)
openFido2Vault ui identities vaultBytes = do
    opened <- openPlaintext ui identities vaultBytes
    pure $ do
        plaintext <- opened
        case decodeVaultPayload Nothing plaintext of
            Right key -> Right key
            Left PayloadNotASigningKey -> Left notOpened
            Left refusal -> Left (Fido2VaultRefused (VaultPayloadRefused refusal))

-- | The plaintext of a vault, once it has opened.
openPlaintext
    :: PluginUi
    -> NonEmpty Fido2Identity
    -> ByteString
    -> IO (Either Fido2Refusal ByteString)
openPlaintext ui identities vaultBytes =
    either (Left . openRefusal) Right
        <$> openWithPlugins ui (identity <$> identities) vaultBytes
  where
    identity (Fido2Identity i) = i

{- | The vault bytes of the same key sealed to a new set of recipients,
opened with one of the old vault's identities. Nothing is written and
the vault given is not changed. Effects: the plugin processes.
-}
rekeyFido2Vault
    :: PluginUi
    -> NonEmpty Fido2Identity
    -> NonEmpty Fido2Recipient
    -> ByteString
    -> IO (Either Fido2Refusal ByteString)
rekeyFido2Vault ui identities recipients vaultBytes = do
    opened <- openPlaintext ui identities vaultBytes
    case opened of
        Left refusal -> pure (Left refusal)
        Right plaintext -> case decodeVaultPayload Nothing plaintext of
            Right _ -> sealPlaintext ui recipients plaintext
            Left PayloadNotASigningKey -> pure (Left notOpened)
            Left refusal ->
                pure (Left (Fido2VaultRefused (VaultPayloadRefused refusal)))

notOpened :: Fido2Refusal
notOpened = Fido2VaultRefused VaultNotOpened

-- | What a plugin refusal while opening means: the one opening refusal.
openRefusal :: PluginRefusal -> Fido2Refusal
openRefusal = \case
    PluginBinaryNotFound binary -> Fido2PluginMissing binary
    _ -> notOpened

-- | What a plugin refusal while sealing means.
sealRefusal :: PluginRefusal -> Fido2Refusal
sealRefusal = \case
    PluginBinaryNotFound binary -> Fido2PluginMissing binary
    refusal -> Fido2PluginFailed (renderPluginRefusal refusal)

-- | One line naming the refusal, carrying no secret.
renderFido2Refusal :: Fido2Refusal -> Text
renderFido2Refusal = \case
    NotAFido2Recipient text ->
        "not a fido2-hmac recipient" <> shown text
    NotAFido2Identity ->
        "the identity file holds no fido2-hmac identity, or a line that is none"
    NoFido2Recipients -> "no fido2-hmac recipient was given"
    Fido2PluginMissing binary ->
        "plugin not found on the PATH: " <> binary
    Fido2PluginFailed message -> message
    Fido2VaultRefused refusal -> renderVaultRefusal refusal
  where
    -- only what looks like a recipient is repeated: a mistaken identity
    -- must not be echoed back
    shown text
        | "age1" `T.isPrefixOf` text =
            ": " <> T.map (\c -> if isControl c then ' ' else c) text
        | otherwise = ""
