{- |
Module      : Cardano.Wallet.Tools.Vault.Payload
Description : What a vault holds: a payment signing key
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The plaintext of a vault, independent of how the vault is encrypted.

The writer emits one format only, v1: the key's @cardano-cli@ text
envelope, type @PaymentSigningKeyShelley_ed25519@, so any age tool
opens a vault and yields an ordinary key file.

The reader accepts v1 and the @cardano-tx-tools@ @tx-sign vault@ JSON
payload (@{"cardanoTxSignVault":{"version":1,"identities":{...}}}@)
with a @cardano-cli-skey@ source, choosing the identity by label.
-}
module Cardano.Wallet.Tools.Vault.Payload
    ( -- * Key
      PaymentSigningKey
    , signerFromKey

      -- * Writing
    , encodeV1Payload

      -- * Reading
    , IdentitySelector (..)
    , parseSigningKeyEnvelope
    , decodeVaultPayload

      -- * Refusals
    , VaultPayloadRefusal (..)
    , renderVaultPayloadRefusal
    ) where

import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , Signer (..)
    , TxBodyBytes (..)
    )
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Data.Aeson (FromJSON (..), Value, withObject, (.:), (.:?))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.Types qualified as Aeson
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.List (sort)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE

-- | One Ed25519 payment signing key. It has no rendering of its bytes.
newtype PaymentSigningKey = PaymentSigningKey Ed25519.SecretKey

instance Show PaymentSigningKey where
    show _ = "<signing key>"

-- | A tx-sign identity label.
newtype IdentitySelector = IdentitySelector Text
    deriving stock (Eq, Show)

-- | Why a plaintext did not yield a key. None carries key bytes.
data VaultPayloadRefusal
    = -- | not a payment signing-key envelope, or a malformed payload
      PayloadNotASigningKey
    | -- | the chosen identity is not among the available labels
      PayloadIdentityMissing (Maybe IdentitySelector) [Text]
    | -- | the chosen identity's source kind is not a @cardano-cli@ key
      PayloadSourceUnsupported Text
    deriving stock (Eq, Show)

-- | The signer for a key: one detached vkey witness over a body.
signerFromKey :: (Applicative m) => PaymentSigningKey -> Signer m
signerFromKey (PaymentSigningKey secret) =
    Signer $ \(TxBodyBytes body) ->
        pure
            DetachedWitness
                { detachedWitnessVKey = BA.convert public
                , detachedWitnessSignature =
                    BA.convert (Ed25519.sign secret public body)
                }
  where
    public = Ed25519.toPublic secret

-- | The v1 plaintext: the key's @cardano-cli@ text envelope.
encodeV1Payload :: PaymentSigningKey -> ByteString
encodeV1Payload (PaymentSigningKey secret) =
    BS.concat
        [ "{\"type\":\"PaymentSigningKeyShelley_ed25519\""
        , ",\"description\":\"Payment Signing Key\""
        , ",\"cborHex\":\"5820"
        , B16.encode (BA.convert secret)
        , "\"}"
        ]

-- | A @cardano-cli@ payment signing-key text envelope, read.
parseSigningKeyEnvelope
    :: ByteString -> Either VaultPayloadRefusal PaymentSigningKey
parseSigningKeyEnvelope =
    maybe (Left PayloadNotASigningKey) keyFromEnvelopeValue
        . Aeson.decodeStrict'

-- | The @type@ and @cborHex@ of a @cardano-cli@ text envelope.
data Envelope = Envelope Text Text

instance FromJSON Envelope where
    parseJSON = withObject "Envelope" $ \o ->
        Envelope <$> o .: "type" <*> o .: "cborHex"

-- | The key a text-envelope JSON value holds, if it holds a supported one.
keyFromEnvelopeValue
    :: Value -> Either VaultPayloadRefusal PaymentSigningKey
keyFromEnvelopeValue value = do
    Envelope keyType cborHex <-
        maybe (Left PayloadNotASigningKey) Right $
            Aeson.parseMaybe parseJSON value
    refuseUnless (keyType `elem` paymentKeyTypes)
    cbor <- refuseLeft (B16.decode (TE.encodeUtf8 cborHex))
    keyBytes <- case BS.splitAt 2 cbor of
        (header, bytes)
            | header == BS.pack [0x58, 0x20] && BS.length bytes == 32 ->
                Right bytes
        _ -> Left PayloadNotASigningKey
    case Ed25519.secretKey keyBytes of
        CryptoPassed secret -> Right (PaymentSigningKey secret)
        CryptoFailed _ -> Left PayloadNotASigningKey
  where
    refuseUnless ok = if ok then Right () else Left PayloadNotASigningKey
    refuseLeft = either (const (Left PayloadNotASigningKey)) Right

-- | The envelope types that hold one 32-byte Ed25519 payment signing key.
paymentKeyTypes :: [Text]
paymentKeyTypes =
    [ "PaymentSigningKeyShelley_ed25519"
    , "GenesisUTxOSigningKey_ed25519"
    ]

{- | A vault plaintext, read: a v1 envelope, or a tx-sign payload from
which the selected identity (else the single one) is taken.
-}
decodeVaultPayload
    :: Maybe IdentitySelector
    -> ByteString
    -> Either VaultPayloadRefusal PaymentSigningKey
decodeVaultPayload selector plaintext =
    case Aeson.decodeStrict' plaintext of
        Just (Aeson.Object top)
            | Just vault <- KeyMap.lookup "cardanoTxSignVault" top ->
                txSignKey selector vault
        Just value -> keyFromEnvelopeValue value
        Nothing -> Left PayloadNotASigningKey

-- | The parts of a tx-sign vault this reader uses.
data TxSignVault = TxSignVault Int (KeyMap TxSignIdentity)

-- | One identity: its own label and where its key comes from.
data TxSignIdentity = TxSignIdentity Text TxSignSource

-- | A source kind, and the envelope it carries when it is a key file.
data TxSignSource = TxSignSource Text (Maybe Value)

instance FromJSON TxSignVault where
    parseJSON = withObject "TxSignVault" $ \o ->
        TxSignVault <$> o .: "version" <*> o .: "identities"

instance FromJSON TxSignIdentity where
    parseJSON = withObject "TxSignIdentity" $ \o ->
        TxSignIdentity <$> o .: "label" <*> o .: "source"

instance FromJSON TxSignSource where
    parseJSON = withObject "TxSignSource" $ \o ->
        TxSignSource <$> o .: "kind" <*> o .:? "keyEnvelope"

-- | The key of the chosen identity of a tx-sign vault value.
txSignKey
    :: Maybe IdentitySelector
    -> Value
    -> Either VaultPayloadRefusal PaymentSigningKey
txSignKey selector value = do
    TxSignVault version identities <-
        maybe (Left PayloadNotASigningKey) Right $
            Aeson.parseMaybe parseJSON value
    if version == 1 && all labelled (KeyMap.toList identities)
        then Right ()
        else Left PayloadNotASigningKey
    TxSignIdentity _ (TxSignSource kind envelope) <-
        chosen identities
    case (kind, envelope) of
        ("cardano-cli-skey", Just keyEnvelope) ->
            keyFromEnvelopeValue keyEnvelope
        ("cardano-cli-skey", Nothing) -> Left PayloadNotASigningKey
        _ -> Left (PayloadSourceUnsupported kind)
  where
    labelled (name, TxSignIdentity label _) = Key.toText name == label
    chosen identities =
        let labels = sort (Key.toText <$> KeyMap.keys identities)
            missing = Left (PayloadIdentityMissing selector labels)
        in  case selector of
                Just (IdentitySelector asked) ->
                    maybe missing Right $
                        KeyMap.lookup (Key.fromText asked) identities
                Nothing -> case KeyMap.elems identities of
                    [only] -> Right only
                    _ -> missing

-- | One line naming the refusal, carrying no key.
renderVaultPayloadRefusal :: VaultPayloadRefusal -> Text
renderVaultPayloadRefusal = \case
    PayloadNotASigningKey -> "not a payment signing-key envelope"
    PayloadIdentityMissing (Just (IdentitySelector asked)) labels ->
        "vault identity `"
            <> asked
            <> "` not found; available identities: "
            <> T.intercalate ", " labels
    PayloadIdentityMissing Nothing [] -> "vault holds no identity"
    PayloadIdentityMissing Nothing labels ->
        "vault holds several identities, choose one with --vault-identity: "
            <> T.intercalate ", " labels
    PayloadSourceUnsupported kind ->
        "unsupported vault source kind: " <> kind
