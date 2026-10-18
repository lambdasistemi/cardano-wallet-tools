{- |
Module      : Cardano.Wallet.Tools.Ledger.Envelope
Description : cardano-cli text envelopes of transactions and witnesses
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The JSON text envelope @cardano-cli@ writes around a transaction or a
verification-key witness, in both directions. An unsigned transaction
is the complete Conway transaction (body, empty witness set, validity
flag, auxiliary data) typed @Unwitnessed Tx ConwayEra@; the label
@Tx ConwayEra@ the official tool writes is read as well. A detached
witness is typed @TxWitness ConwayEra@ and described
@Key Witness ShelleyEra@, as the official tool writes it. Pure: no
files, no clock, no network.
-}
module Cardano.Wallet.Tools.Ledger.Envelope
    ( -- * Text envelope
      TextEnvelope (..)
    , EnvelopeRefusal (..)
    , renderEnvelopeRefusal
    , encodeTextEnvelope
    , decodeTextEnvelope
    , textEnvelopeOf

      -- * Unsigned transactions
    , transactionEnvelopeType
    , acceptedTransactionEnvelopeTypes
    , transactionEnvelope
    , decodeTransactionEnvelope

      -- * Detached witnesses
    , witnessEnvelope
    , decodeWitnessEnvelope

      -- * Hex
    , hexText
    , decodeHexText
    ) where

import Cardano.Ledger.Binary
    ( decCBOR
    , decodeFullAnnotator
    , serialize'
    )
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (TopTx, Tx, eraProtVerHigh)
import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , decodeDetachedWitness
    , encodeDetachedWitness
    )
import Control.Monad (unless)
import Data.Aeson
    ( Value (..)
    , eitherDecodeStrict
    , encode
    , object
    , (.=)
    )
import Data.Aeson.Key (fromString)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.ByteString.Lazy qualified as BSL
import Data.Text (Text)
import Data.Text qualified as Text

-- | The text envelope of a transaction or of a detached witness.
data TextEnvelope = TextEnvelope
    { envelopeType :: Text
    -- ^ the @type@ field, naming what the CBOR carries
    , envelopeDescription :: Text
    -- ^ the @description@ field, as the writer spelled it
    , envelopeCborHex :: Text
    -- ^ the @cborHex@ field, the CBOR bytes in hex
    }
    deriving stock (Eq, Show)

-- | Why a text envelope was refused. None names a key.
data EnvelopeRefusal
    = -- | a field of the envelope, and what is wrong with it
      EnvelopeField String String
    | -- | an envelope whose type is not the expected one, naming the
      -- type it carries
      EnvelopeWrongType Text
    deriving stock (Eq, Show)

-- | One line naming the refusal.
renderEnvelopeRefusal :: EnvelopeRefusal -> String
renderEnvelopeRefusal = \case
    EnvelopeField name why -> "the " <> name <> " " <> why
    EnvelopeWrongType found ->
        "the envelope's type is " <> show (Text.unpack found)

-- | The envelope's JSON bytes, as a file holds them.
encodeTextEnvelope :: TextEnvelope -> ByteString
encodeTextEnvelope envelope =
    BSL.toStrict $
        encode $
            object
                [ "type" .= envelopeType envelope
                , "description" .= envelopeDescription envelope
                , "cborHex" .= envelopeCborHex envelope
                ]

{- | The three fields of an envelope read from JSON bytes, without any
check of the type.
-}
decodeTextEnvelope
    :: ByteString -> Either EnvelopeRefusal TextEnvelope
decodeTextEnvelope bytes = do
    value <-
        first
            (const (EnvelopeField "envelope" "is not JSON"))
            (eitherDecodeStrict bytes)
    textEnvelopeOf value

-- | The three fields of an envelope read from a JSON value.
textEnvelopeOf :: Value -> Either EnvelopeRefusal TextEnvelope
textEnvelopeOf = \case
    Object fields ->
        TextEnvelope
            <$> textField "type" fields
            <*> textField "description" fields
            <*> textField "cborHex" fields
    _ -> Left (EnvelopeField "envelope" "is not a JSON object")
  where
    textField name fields = case KeyMap.lookup (fromString name) fields of
        Nothing -> Left (EnvelopeField name "is missing")
        Just (String t) -> Right t
        Just _ -> Left (EnvelopeField name "is not text")

-- | The envelope type written for an unsigned transaction.
transactionEnvelopeType :: Text
transactionEnvelopeType = "Unwitnessed Tx ConwayEra"

{- | The envelope types read for an unsigned transaction: the label
written, and the one the official tool writes.
-}
acceptedTransactionEnvelopeTypes :: [Text]
acceptedTransactionEnvelopeTypes =
    [transactionEnvelopeType, "Tx ConwayEra"]

{- | The text envelope of an unsigned transaction: the complete
transaction's CBOR in hex, serialized at the Conway protocol version.
-}
transactionEnvelope :: Tx TopTx ConwayEra -> TextEnvelope
transactionEnvelope tx =
    TextEnvelope
        { envelopeType = transactionEnvelopeType
        , envelopeDescription = "Ledger Cddl Format"
        , envelopeCborHex =
            Text.pack (hexText (serialize' (eraProtVerHigh @ConwayEra) tx))
        }

{- | The complete Conway transaction an envelope's CBOR carries. A bare
body is not a transaction and does not decode.
-}
decodeTransactionEnvelope
    :: TextEnvelope -> Either String (Tx TopTx ConwayEra)
decodeTransactionEnvelope envelope = do
    payload <- decodeHexText (envelopeCborHex envelope)
    first
        (const "the cborHex does not decode to a Conway transaction")
        ( decodeFullAnnotator
            (eraProtVerHigh @ConwayEra)
            "ConwayTx"
            decCBOR
            (BSL.fromStrict payload)
        )

-- | The envelope type of a detached verification-key witness.
witnessEnvelopeType :: Text
witnessEnvelopeType = "TxWitness ConwayEra"

{- | The text envelope of a detached witness, as the official tool
writes one: the raw array of the key and the signature.
-}
witnessEnvelope :: DetachedWitness -> TextEnvelope
witnessEnvelope witness =
    TextEnvelope
        { envelopeType = witnessEnvelopeType
        , envelopeDescription = "Key Witness ShelleyEra"
        , envelopeCborHex =
            Text.pack (hexText (encodeDetachedWitness witness))
        }

{- | The witness a witness envelope's JSON bytes carry, or the named
refusal. The key is 32 bytes and the signature 64.
-}
decodeWitnessEnvelope
    :: ByteString -> Either EnvelopeRefusal DetachedWitness
decodeWitnessEnvelope bytes = do
    envelope <- decodeTextEnvelope bytes
    unless (envelopeType envelope == witnessEnvelopeType) $
        Left (EnvelopeWrongType (envelopeType envelope))
    payload <-
        first
            (const (EnvelopeField "cborHex" "is not hex"))
            (decodeHexText (envelopeCborHex envelope))
    witness <-
        first
            (const (EnvelopeField "witness" "is not a key witness"))
            (decodeDetachedWitness payload)
    if BS.length (detachedWitnessVKey witness) == 32
        && BS.length (detachedWitnessSignature witness) == 64
        then Right witness
        else
            Left
                ( EnvelopeField
                    "witness"
                    "does not carry a 32-byte key and a 64-byte signature"
                )

-- | Bytes as lowercase hex, the spelling of envelopes and refusals.
hexText :: ByteString -> String
hexText = BC.unpack . B16.encode

-- | Hex text as bytes, or why it is not hex.
decodeHexText :: Text -> Either String ByteString
decodeHexText spelling =
    first
        (const ("is not hex: " <> Text.unpack spelling))
        (B16.decode (BC.pack (Text.unpack spelling)))
