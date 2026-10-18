{- |
Module      : Cardano.Wallet.Tools.Ledger.Bundle
Description : The bundle of unsigned transactions: types, codec, offline checks
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A bundle is what a transaction-building tool hands an offline signer:
one JSON file holding the addresses that must sign and the unsigned
transactions in submission order. This module owns the bundle: its
types, its JSON codec and the offline consistency checks. Everything a
bundle says about itself is checked before it is signed: the recorded
identity is the hash of the decoded transaction's body, the recorded
deadline is the body's validity upper bound, the identities are
distinct, and every key hash a body requires is the key hash of an
address among the bundle's signers. The effects lines are the writer's
claims: carried and shown, never trusted. Whether the signers list is
complete cannot be checked offline. Pure.
-}
module Cardano.Wallet.Tools.Ledger.Bundle
    ( -- * Bundle
      Bundle (..)
    , BundleTransaction (..)
    , bundleVersion

      -- * Codec
    , encodeBundle
    , decodeBundle

      -- * Identity and deadline of a body
    , bodyIdentity
    , bodyDeadline

      -- * Offline checks
    , BundleRefusal (..)
    , bundleRefusals
    , checkBundle
    , renderBundleRefusal
    ) where

import Cardano.Crypto.Hash (hashToBytes)
import Cardano.Ledger.Address (Addr (..), decodeAddrEither)
import Cardano.Ledger.Api.Tx (bodyTxL, txIdTx)
import Cardano.Ledger.Api.Tx.Body
    ( ValidityInterval (..)
    , reqSignerHashesTxBodyL
    , vldtTxBodyL
    )
import Cardano.Ledger.BaseTypes (SlotNo (..), StrictMaybe (..))
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (TopTx, Tx, extractHash)
import Cardano.Ledger.Credential (Credential (..))
import Cardano.Ledger.Keys (unKeyHash)
import Cardano.Ledger.TxIn (TxId (..))
import Cardano.Wallet.Tools.Ledger.Envelope
    ( EnvelopeRefusal (..)
    , TextEnvelope (..)
    , acceptedTransactionEnvelopeTypes
    , decodeHexText
    , decodeTransactionEnvelope
    , hexText
    , textEnvelopeOf
    )
import Codec.Binary.Bech32 qualified as Bech32
import Control.Monad (unless)
import Data.Aeson
    ( FromJSON
    , Value (..)
    , eitherDecodeStrict
    , encode
    , fromJSON
    , object
    , (.=)
    )
import Data.Aeson.Key (fromString)
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.Types (Result (..))
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BSL
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as Text
import Data.Word (Word32, Word64)
import Lens.Micro ((^.))

{- | One unsigned transaction of a bundle: its recorded identity, its
text envelope, its recorded deadline and the effects its writer claims.
The identity and the deadline are the writer's statements about the
transaction; the offline checks prove them against it.
-}
data BundleTransaction = BundleTransaction
    { bundleTxIdentity :: ByteString
    -- ^ the 32 bytes of the body's hash, as the bundle records it
    , bundleTxEnvelope :: TextEnvelope
    -- ^ the transaction's text envelope
    , bundleTxDeadline :: Maybe Word64
    -- ^ the body's validity upper bound as a slot number, or nothing
    , bundleTxEffects :: [Text]
    -- ^ the writer's claims, each one line, shown and never trusted
    }
    deriving stock (Eq, Show)

{- | A bundle: the command name that wrote it, the network magic its
transactions are built for, an opaque state token the writer may set,
the addresses that must sign, and the transactions in submission
order.
-}
data Bundle = Bundle
    { bundleCommand :: Text
    -- ^ the command name that wrote the bundle
    , bundleNetworkMagic :: Word32
    -- ^ the network the transactions are built for
    , bundleStateToken :: Maybe Text
    -- ^ opaque, set by the caller and never interpreted
    , bundleSigners :: NonEmpty Text
    -- ^ the bech32 addresses that must sign
    , bundleTransactions :: NonEmpty BundleTransaction
    -- ^ the transactions in submission order
    }
    deriving stock (Eq, Show)

-- | Why a bundle was refused. None names a key or a passphrase.
data BundleRefusal
    = -- | the bundle's version, which this codec does not read
      BundleUnknownVersion Word
    | -- | a field of the bundle, and what is wrong with it
      BundleField String String
    | -- | an envelope whose type is not one of the accepted ones,
      -- naming the type it carries
      BundleEnvelopeWrongType Text
    | -- | an envelope whose CBOR is not a decodable Conway transaction,
      -- naming the identity it is recorded under, in hex
      BundleEnvelopeUndecodable String
    | -- | a recorded identity that is not the hash of the transaction's
      -- body, carrying the recorded and the actual hash
      BundleIdentityMismatch ByteString ByteString
    | -- | a recorded deadline that is not the body's validity upper
      -- bound, carrying the recorded and the actual bound and the recorded
      -- identity
      BundleDeadlineMismatch (Maybe Word64) (Maybe Word64) ByteString
    | -- | an identity recorded for two transactions
      BundleDuplicateIdentity ByteString
    | -- | a key hash a body requires and no signer address covers,
      -- carrying the key hash and the recorded identity
      BundleSignerNotCovered ByteString ByteString
    deriving stock (Eq, Show)

{- | One line naming the failed check, carrying what it concerns and no
secret. The line starts with the name of the check and a colon:
@version@, @field@, @envelope-type@, @envelope@, @identity@,
@deadline@, @distinct-identities@ or @signers@.
-}
renderBundleRefusal :: BundleRefusal -> String
renderBundleRefusal = \case
    BundleUnknownVersion v ->
        "version: the bundle's version is "
            <> show v
            <> ", and this codec reads only version "
            <> show bundleVersion
    BundleField name why ->
        "field: the bundle's " <> name <> " field " <> why
    BundleEnvelopeWrongType found ->
        "envelope-type: the transaction envelope's type is "
            <> show (Text.unpack found)
            <> ", not one of "
            <> show (map Text.unpack acceptedTransactionEnvelopeTypes)
    BundleEnvelopeUndecodable identity ->
        "envelope: the transaction envelope recorded as "
            <> identity
            <> " does not decode to a Conway transaction"
    BundleIdentityMismatch recorded actual ->
        "identity: the transaction's recorded identity "
            <> hexText recorded
            <> " is not the hash of its body, "
            <> hexText actual
    BundleDeadlineMismatch recorded actual identity ->
        "deadline: the transaction "
            <> hexText identity
            <> " records deadline "
            <> boundText recorded
            <> " and its body's validity upper bound is "
            <> boundText actual
    BundleDuplicateIdentity identity ->
        "distinct-identities: the identity "
            <> hexText identity
            <> " names two transactions"
    BundleSignerNotCovered keyHash identity ->
        "signers: the key hash "
            <> hexText keyHash
            <> " is required by the transaction "
            <> hexText identity
            <> " and no signer address covers it"
  where
    boundText = maybe "none" show

{- | The version this codec writes and the only one it reads. A bundle
carrying any other version is refused by name.
-}
bundleVersion :: Word
bundleVersion = 1

{- | The hash of a transaction's body, as the ledger computes a
transaction id: the identity a bundle records.
-}
bodyIdentity :: Tx TopTx ConwayEra -> ByteString
bodyIdentity tx = hashToBytes (extractHash h)
  where
    TxId h = txIdTx tx

-- | The body's validity upper bound, read as the deadline it is.
bodyDeadline :: Tx TopTx ConwayEra -> Maybe Word64
bodyDeadline tx = case tx ^. bodyTxL . vldtTxBodyL of
    ValidityInterval _ (SJust (SlotNo n)) -> Just n
    ValidityInterval _ SNothing -> Nothing

{- | The JSON bytes of a bundle: version, command, network magic, state
token, signers and transactions in submission order. Deterministic: the
same bundle encodes to the same bytes.
-}
encodeBundle :: Bundle -> ByteString
encodeBundle bundle = BSL.toStrict (encode (bundleValue bundle))
  where
    bundleValue b =
        object
            [ "version" .= bundleVersion
            , "command" .= bundleCommand b
            , "networkMagic" .= bundleNetworkMagic b
            , "stateToken" .= bundleStateToken b
            , "signers" .= toList (bundleSigners b)
            , "transactions" .= map txValue (toList (bundleTransactions b))
            ]
    txValue tx =
        object
            [ "identity" .= Text.pack (hexText (bundleTxIdentity tx))
            , "envelope" .= envelopeValue (bundleTxEnvelope tx)
            , "deadline" .= bundleTxDeadline tx
            , "effects" .= bundleTxEffects tx
            ]
    envelopeValue envelope =
        object
            [ "type" .= envelopeType envelope
            , "description" .= envelopeDescription envelope
            , "cborHex" .= envelopeCborHex envelope
            ]

{- | A bundle read back from its JSON bytes, or the named refusal: an
unknown version, a missing or malformed field, an envelope of the wrong
type. The transactions are not decoded here; the offline checks own the
undecodable-envelope refusal.
-}
decodeBundle :: ByteString -> Either BundleRefusal Bundle
decodeBundle bytes = do
    value <-
        first
            (const (BundleField "bundle" "is not JSON"))
            (eitherDecodeStrict bytes)
    fields <- case value of
        Object o -> Right o
        _ -> Left (BundleField "bundle" "is not a JSON object")
    version <- numberField "version" fields
    unless (version == bundleVersion) $
        Left (BundleUnknownVersion version)
    command <- textField "command" fields
    magic <- numberField "networkMagic" fields
    stateToken <- case fieldOf "stateToken" fields of
        Nothing -> Right Nothing
        Just Null -> Right Nothing
        Just (String t) -> Right (Just t)
        Just _ -> Left (BundleField "stateToken" "is not text or null")
    signers <- signersOf fields
    transactions <- transactionsOf fields
    pure
        Bundle
            { bundleCommand = command
            , bundleNetworkMagic = magic
            , bundleStateToken = stateToken
            , bundleSigners = signers
            , bundleTransactions = transactions
            }

{- | Every failed offline check, in the order of the checks: envelopes
that do not decode, identities that are not the body's hash, deadlines
that are not the body's validity upper bound, identities recorded for
two transactions, and required key hashes no signer address covers;
within a check, in bundle order. A transaction whose envelope does not
decode is judged by no further check but the distinct identities.
-}
bundleRefusals :: Bundle -> [BundleRefusal]
bundleRefusals bundle =
    undecodable
        <> identities
        <> deadlines
        <> duplicates
        <> uncovered
  where
    transactions = toList (bundleTransactions bundle)
    entries =
        [ (tx, decodeTransactionEnvelope (bundleTxEnvelope tx))
        | tx <- transactions
        ]
    decoded = [(tx, body) | (tx, Right body) <- entries]
    undecodable =
        [ BundleEnvelopeUndecodable (hexText (bundleTxIdentity tx))
        | (tx, Left _) <- entries
        ]
    identities =
        [ BundleIdentityMismatch (bundleTxIdentity tx) actual
        | (tx, body) <- decoded
        , let actual = bodyIdentity body
        , actual /= bundleTxIdentity tx
        ]
    deadlines =
        [ BundleDeadlineMismatch
            (bundleTxDeadline tx)
            actual
            (bundleTxIdentity tx)
        | (tx, body) <- decoded
        , let actual = bodyDeadline body
        , actual /= bundleTxDeadline tx
        ]
    duplicates =
        BundleDuplicateIdentity
            <$> repeated (map bundleTxIdentity transactions)
    covered = signerKeyHashes (bundleSigners bundle)
    uncovered =
        [ BundleSignerNotCovered required (bundleTxIdentity tx)
        | (tx, body) <- decoded
        , hash <- toList (body ^. bodyTxL . reqSignerHashesTxBodyL)
        , let required = hashToBytes (unKeyHash hash)
        , required `notElem` covered
        ]

-- | The first refusal of 'bundleRefusals', or nothing when all checks pass.
checkBundle :: Bundle -> Either BundleRefusal ()
checkBundle bundle = case bundleRefusals bundle of
    [] -> Right ()
    refusal : _ -> Left refusal

{- | The identities that occur more than once, each once, in the order
their first repeat appears.
-}
repeated :: [ByteString] -> [ByteString]
repeated = reverse . fst . foldl' step ([], Set.empty)
  where
    step (reported, seen) identity
        | identity `Set.member` seen && identity `notElem` reported =
            (identity : reported, seen)
        | otherwise = (reported, Set.insert identity seen)

-- | The payment key hashes of the signers' addresses, as bytes.
signerKeyHashes :: NonEmpty Text -> [ByteString]
signerKeyHashes signers =
    [ hashToBytes (unKeyHash hash)
    | spelling <- toList signers
    , Right (Addr _ (KeyHashObj hash) _) <-
        [addressOfText "signers" spelling]
    ]

-- | A signer's address, or the field refusal for its spelling.
addressOfText :: String -> Text -> Either BundleRefusal Addr
addressOfText fieldName spelling = do
    (_, dataPart) <- first (const refused) (Bech32.decode spelling)
    bytes <- maybe (Left refused) Right (Bech32.dataPartToBytes dataPart)
    first (const refused) (decodeAddrEither bytes)
  where
    refused =
        BundleField
            fieldName
            ("is not a bech32 address: " <> show (Text.unpack spelling))

-- * Field readers over the codec's own JSON

-- | A field of an object, in the codec's spelling.
fieldOf :: String -> KeyMap Value -> Maybe Value
fieldOf name = KeyMap.lookup (fromString name)

-- | A text field, refusing by name when missing or not text.
textField :: String -> KeyMap Value -> Either BundleRefusal Text
textField name fields = case fieldOf name fields of
    Nothing -> Left (BundleField name "is missing")
    Just (String t) -> Right t
    Just _ -> Left (BundleField name "is not text")

-- | A number field, read at the width given.
numberField
    :: forall w
     . (FromJSON w)
    => String
    -> KeyMap Value
    -> Either BundleRefusal w
numberField name fields = case fieldOf name fields of
    Nothing -> Left (BundleField name "is missing")
    Just v -> case fromJSON v of
        Success w -> Right w
        Error _ -> Left (BundleField name "is not a number")

-- | A deadline: a number of slots, or nothing.
deadlineOf :: KeyMap Value -> Either BundleRefusal (Maybe Word64)
deadlineOf fields = case fieldOf "deadline" fields of
    Nothing -> Left (BundleField "deadline" "is missing")
    Just Null -> Right Nothing
    Just (Number _) -> Just <$> numberField "deadline" fields
    Just _ -> Left (BundleField "deadline" "is not a slot number or null")

-- | The signers list: non-empty, every entry a bech32 address.
signersOf :: KeyMap Value -> Either BundleRefusal (NonEmpty Text)
signersOf fields = case fieldOf "signers" fields of
    Nothing -> Left (BundleField "signers" "is missing")
    Just (Array entries) -> do
        spellings <- traverse asAddress (toList entries)
        nonEmpty "signers" spellings
    Just _ -> Left (BundleField "signers" "is not a list")
  where
    asAddress = \case
        String t -> t <$ addressOfText "signers" t
        _ -> Left (BundleField "signers" "is not text")

-- | The transaction list: non-empty, every entry a bundle transaction.
transactionsOf
    :: KeyMap Value -> Either BundleRefusal (NonEmpty BundleTransaction)
transactionsOf fields = case fieldOf "transactions" fields of
    Nothing -> Left (BundleField "transactions" "is missing")
    Just (Array entries) -> do
        transactions <- traverse asTransaction (toList entries)
        nonEmpty "transactions" transactions
    Just _ -> Left (BundleField "transactions" "is not a list")

nonEmpty :: String -> [a] -> Either BundleRefusal (NonEmpty a)
nonEmpty name = \case
    [] -> Left (BundleField name "is empty")
    one : more -> Right (one :| more)

-- | One transaction, as the codec reads it.
asTransaction :: Value -> Either BundleRefusal BundleTransaction
asTransaction = \case
    Object o -> do
        identity <- identityOf o
        envelope <- envelopeOf o
        deadline <- deadlineOf o
        effects <- effectsOf o
        pure
            BundleTransaction
                { bundleTxIdentity = identity
                , bundleTxEnvelope = envelope
                , bundleTxDeadline = deadline
                , bundleTxEffects = effects
                }
    _ -> Left (BundleField "transactions" "is not a JSON object")

-- | The recorded identity: 64 hex digits, 32 bytes.
identityOf :: KeyMap Value -> Either BundleRefusal ByteString
identityOf fields = do
    spelling <- textField "identity" fields
    bytes <-
        first
            (const (BundleField "identity" "is not 64 hex digits"))
            (decodeHexText spelling)
    if BS.length bytes == 32
        then Right bytes
        else Left (BundleField "identity" "is not 32 bytes")

-- | The transaction's envelope, its type accepted from either label.
envelopeOf :: KeyMap Value -> Either BundleRefusal TextEnvelope
envelopeOf fields = do
    value <-
        maybe
            (Left (BundleField "envelope" "is missing"))
            Right
            (fieldOf "envelope" fields)
    envelope <- first bundleRefusalOf (textEnvelopeOf value)
    unless (envelopeType envelope `elem` acceptedTransactionEnvelopeTypes) $
        Left (BundleEnvelopeWrongType (envelopeType envelope))
    envelope
        <$ first
            (const (BundleField "envelope.cborHex" "is not hex"))
            (decodeHexText (envelopeCborHex envelope))
  where
    bundleRefusalOf = \case
        EnvelopeField name why -> BundleField name why
        EnvelopeWrongType found -> BundleEnvelopeWrongType found

-- | The effects: single-line texts.
effectsOf :: KeyMap Value -> Either BundleRefusal [Text]
effectsOf fields = case fieldOf "effects" fields of
    Nothing -> Left (BundleField "effects" "is missing")
    Just (Array entries) -> traverse effect (toList entries)
    Just _ -> Left (BundleField "effects" "is not a list")
  where
    effect = \case
        String t
            | Text.any (\c -> c == '\n' || c == '\r') t ->
                Left (BundleField "effects" "carries a line break")
            | otherwise -> Right t
        _ -> Left (BundleField "effects" "is not text")
