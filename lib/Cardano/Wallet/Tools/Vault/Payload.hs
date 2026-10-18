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
with a @cardano-cli-skey@ or a @cardano-addresses-addr-xsk@ source,
choosing the identity by label.
-}
module Cardano.Wallet.Tools.Vault.Payload
    ( -- * Keys
      PaymentSigningKey
    , ExtendedSigningKey
    , OpenedKey (..)
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
import Codec.Binary.Bech32 qualified as Bech32
import Crypto.ECC.Edwards25519 qualified as Edwards25519
import Crypto.Error (CryptoFailable (..), throwCryptoError)
import Crypto.Hash
    ( Blake2b_224 (..)
    , Blake2b_256 (..)
    , Digest
    , SHA512 (..)
    , hashWith
    )
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

{- | One plain Ed25519 payment signing key, as @cardano-cli@ writes it:
the one key a vault is written from. It has no rendering of its bytes.
-}
newtype PaymentSigningKey = PaymentSigningKey Ed25519.SecretKey

instance Show PaymentSigningKey where
    show _ = "<signing key>"

{- | One extended BIP32-Ed25519 payment signing key, as
@cardano-addresses@ writes it (@addr_xsk@): the scalar kL, the nonce
prefix kR and the chain code, with the verification key kL·B. A vault is
read to it and never written from it. It has no rendering of its bytes.
-}
data ExtendedSigningKey = ExtendedSigningKey
    { extendedScalar :: !Edwards25519.Scalar
    , extendedPrefix :: !ByteString
    , extendedChainCode :: !ByteString
    , extendedPublic :: !ByteString
    }

instance Show ExtendedSigningKey where
    show _ = "<extended signing key>"

-- | The key a vault opens to: a plain key or an extended one.
data OpenedKey
    = OpenedPlain PaymentSigningKey
    | OpenedExtended ExtendedSigningKey
    deriving stock (Show)

-- | A tx-sign identity label.
newtype IdentitySelector = IdentitySelector Text
    deriving stock (Eq, Show)

-- | Why a plaintext did not yield a key. None carries key bytes.
data VaultPayloadRefusal
    = -- | not a payment signing-key envelope, or a malformed payload
      PayloadNotASigningKey
    | -- | the chosen identity is not among the available labels
      PayloadIdentityMissing (Maybe IdentitySelector) [Text]
    | -- | the chosen identity's source kind is not one this reader reads
      PayloadSourceUnsupported Text
    | -- | the chosen identity stores a key hash that is not its key's
      PayloadKeyHashMismatch Text
    deriving stock (Eq, Show)

{- | The signer for a key: one detached vkey witness over a body. The
witness signs blake2b-256 of the body bytes it is given, the digest a
transaction id is.
-}
signerFromKey :: (Applicative m) => OpenedKey -> Signer m
signerFromKey key =
    Signer $ \(TxBodyBytes body) ->
        pure
            DetachedWitness
                { detachedWitnessVKey = verificationKey key
                , detachedWitnessSignature =
                    signMessage key (BA.convert (hashWith Blake2b_256 body))
                }

-- | The 32-byte verification key of a key.
verificationKey :: OpenedKey -> ByteString
verificationKey = \case
    OpenedPlain (PaymentSigningKey secret) ->
        BA.convert (Ed25519.toPublic secret)
    OpenedExtended extended -> extendedPublic extended

{- | The Ed25519 signature of a message, 64 bytes, verifying under the
key's verification key. An extended key signs by the rule
cardano-crypto uses: the nonce comes from kR, the response from kL.
-}
signMessage :: OpenedKey -> ByteString -> ByteString
signMessage = \case
    OpenedPlain (PaymentSigningKey secret) ->
        BA.convert . Ed25519.sign secret (Ed25519.toPublic secret)
    OpenedExtended
        ExtendedSigningKey{extendedScalar, extendedPrefix, extendedPublic} ->
            \message ->
                let nonce = scalarOfDigest (hashWith SHA512 (extendedPrefix <> message))
                    commitment = Edwards25519.pointEncode (Edwards25519.toPoint nonce)
                    challenge =
                        scalarOfDigest
                            (hashWith SHA512 (commitment <> extendedPublic <> message))
                    response =
                        Edwards25519.scalarAdd
                            nonce
                            (Edwards25519.scalarMul challenge extendedScalar)
                in  commitment <> Edwards25519.scalarEncode response

{- | A scalar from a SHA-512 digest, reduced modulo the group order. A
64-byte input always decodes.
-}
scalarOfDigest :: Digest SHA512 -> Edwards25519.Scalar
scalarOfDigest = throwCryptoError . Edwards25519.scalarDecodeLong

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
    -> Either VaultPayloadRefusal OpenedKey
decodeVaultPayload selector plaintext =
    case Aeson.decodeStrict' plaintext of
        Just (Aeson.Object top)
            | Just vault <- KeyMap.lookup "cardanoTxSignVault" top ->
                txSignKey selector vault
        Just value -> OpenedPlain <$> keyFromEnvelopeValue value
        Nothing -> Left PayloadNotASigningKey

-- | The parts of a tx-sign vault this reader uses.
data TxSignVault = TxSignVault Int (KeyMap TxSignIdentity)

-- | One identity: its own label, the key hash it stores, where its key comes from.
data TxSignIdentity = TxSignIdentity Text Text TxSignSource

-- | A source kind, with the key envelope or the bech32 key it carries.
data TxSignSource = TxSignSource Text (Maybe Value) (Maybe Text)

instance FromJSON TxSignVault where
    parseJSON = withObject "TxSignVault" $ \o ->
        TxSignVault <$> o .: "version" <*> o .: "identities"

instance FromJSON TxSignIdentity where
    parseJSON = withObject "TxSignIdentity" $ \o ->
        TxSignIdentity
            <$> o .: "label"
            <*> o .: "keyHash"
            <*> o .: "source"

instance FromJSON TxSignSource where
    parseJSON = withObject "TxSignSource" $ \o ->
        TxSignSource
            <$> o .: "kind"
            <*> o .:? "keyEnvelope"
            <*> o .:? "bech32"

-- | The key of the chosen identity of a tx-sign vault value.
txSignKey
    :: Maybe IdentitySelector
    -> Value
    -> Either VaultPayloadRefusal OpenedKey
txSignKey selector value = do
    TxSignVault version identities <-
        maybe (Left PayloadNotASigningKey) Right $
            Aeson.parseMaybe parseJSON value
    if version == 1 && all labelled (KeyMap.toList identities)
        then Right ()
        else Left PayloadNotASigningKey
    TxSignIdentity label keyHash (TxSignSource kind envelope bech32) <-
        chosen identities
    key <- case (kind, envelope, bech32) of
        ("cardano-cli-skey", Just keyEnvelope, _) ->
            OpenedPlain <$> keyFromEnvelopeValue keyEnvelope
        ("cardano-cli-skey", Nothing, _) -> Left PayloadNotASigningKey
        ("cardano-addresses-addr-xsk", _, Just text) ->
            OpenedExtended <$> keyFromAddrXsk text
        ("cardano-addresses-addr-xsk", _, Nothing) ->
            Left PayloadNotASigningKey
        _ -> Left (PayloadSourceUnsupported kind)
    if storesHashOf keyHash key
        then Right key
        else Left (PayloadKeyHashMismatch label)
  where
    labelled (name, TxSignIdentity label _ _) = Key.toText name == label
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

{- | Whether a stored hex key hash is blake2b-224 of the verification
key of the key; a stored value that is not hex is no match.
-}
storesHashOf :: Text -> OpenedKey -> Bool
storesHashOf stored key =
    B16.decode (TE.encodeUtf8 stored)
        == Right (BA.convert (hashWith Blake2b_224 (verificationKey key)))

{- | The extended key a @cardano-addresses@ @addr_xsk@ bech32 string holds:
96 bytes, kL and kR then the chain code.
-}
keyFromAddrXsk
    :: Text -> Either VaultPayloadRefusal ExtendedSigningKey
keyFromAddrXsk text = do
    (prefix, dataPart) <- refuseLeft (Bech32.decodeLenient text)
    bytes <- case Bech32.dataPartToBytes dataPart of
        Just raw
            | Bech32.humanReadablePartToText prefix == "addr_xsk"
            , BS.length raw == 96 ->
                Right raw
        _ -> Left PayloadNotASigningKey
    let (scalarBytes, afterScalar) = BS.splitAt 32 bytes
        (prefixBytes, chainCode) = BS.splitAt 32 afterScalar
    scalar <- case Edwards25519.scalarDecodeLong scalarBytes of
        CryptoPassed decoded -> Right decoded
        CryptoFailed _ -> Left PayloadNotASigningKey
    Right
        ExtendedSigningKey
            { extendedScalar = scalar
            , extendedPrefix = prefixBytes
            , extendedChainCode = chainCode
            , extendedPublic =
                Edwards25519.pointEncode (Edwards25519.toPoint scalar)
            }
  where
    refuseLeft = either (const (Left PayloadNotASigningKey)) Right

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
    PayloadKeyHashMismatch label ->
        "vault identity `"
            <> label
            <> "` stores a key hash that is not the hash of its signing key"
