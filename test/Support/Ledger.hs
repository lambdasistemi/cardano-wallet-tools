{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}

{- |
Module      : Support.Ledger
Description : Producers and oracles for the ledger specs
License     : Apache-2.0

Everything a ledger spec compares against is obtained here from a
producer, never typed beside the assertion: transaction identities from
the ledger's own transaction id, signatures from the signing primitive
over the identity bytes, addresses from the ledger's address
serialisation, envelope bytes from the ledger's serialiser. None of it
calls the library under test.
-}
module Support.Ledger
    ( -- * Fixtures
      readBundleFixture
    , readBundleHexFixture
    , readSigningKeyFixture
    , readOfficialTransaction

      -- * Keys and addresses
    , fixedKey
    , strangerKey
    , thirdKey
    , runtimeKey
    , verKeyBytes
    , requiredHashOf
    , keyHashBytes
    , addressOf
    , addressText
    , fixedSigner
    , paymentKeyHashOfAddress

      -- * Bodies and transactions
    , ConwayTx
    , ConwayTxBody
    , txOf
    , syntheticBody
    , syntheticBodyRequiring
    , spendingBody
    , unboundedBody
    , chainedBodies
    , chainedPair
    , funding
    , paymentOutput
    , scriptOutput
    , outputsOfBodies
    , bodyDeadlineOf
    , deadlineOfTx
    , requiredOf

      -- * Independent oracles
    , identityOf
    , independentBodyHash
    , envelopeOfTx
    , txFromCbor
    , witnessOver
    , witnessOverMessage
    , bodyBytesOf
    , witnessesIn
    , witnessCborHex

      -- * Bundles
    , bundleTxOf
    , bundleTxRecording
    , sampleBundle
    , tamperJson
    , fixtureBundle
    , bundleOf
    , magic
    , flippedIdentity
    , withFirst
    , hexOf
    , hexTextOf
    , txInHex
    ) where

import Cardano.Crypto.DSIGN
    ( Ed25519DSIGN
    , SignKeyDSIGN
    , SignedDSIGN (..)
    , deriveVerKeyDSIGN
    , rawDeserialiseSignKeyDSIGN
    , rawSerialiseSigDSIGN
    , rawSerialiseVerKeyDSIGN
    , signDSIGN
    )
import Cardano.Crypto.Hash
    ( Blake2b_256
    , hashFromBytes
    , hashToBytes
    , hashWith
    )
import Cardano.Ledger.Address (Addr (..), serialiseAddr)
import Cardano.Ledger.Api.Tx
    ( addrTxWitsL
    , bodyTxL
    , mkBasicTx
    , txIdTx
    , witsTxL
    )
import Cardano.Ledger.Api.Tx.Body
    ( ValidityInterval (..)
    , feeTxBodyL
    , inputsTxBodyL
    , mkBasicTxBody
    , outputsTxBodyL
    , reqSignerHashesTxBodyL
    , vldtTxBodyL
    )
import Cardano.Ledger.Api.Tx.Out (TxOut, mkBasicTxOut)
import Cardano.Ledger.BaseTypes
    ( Network (Testnet)
    , SlotNo (..)
    , StrictMaybe (..)
    , TxIx (..)
    )
import Cardano.Ledger.Binary
    ( decCBOR
    , decodeFullAnnotator
    , serialize
    , serialize'
    )
import Cardano.Ledger.Coin (Coin (..))
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core
    ( TopTx
    , Tx
    , TxBody
    , eraProtVerHigh
    , extractHash
    )
import Cardano.Ledger.Credential
    ( Credential (KeyHashObj, ScriptHashObj)
    , StakeReference (StakeRefNull)
    )
import Cardano.Ledger.Hashes (ScriptHash (..), unsafeMakeSafeHash)
import Cardano.Ledger.Keys
    ( KeyHash
    , KeyRole (Guard)
    , VKey (..)
    , WitVKey (..)
    , hashKey
    , unKeyHash
    )
import Cardano.Ledger.Mary.Value (MaryValue (..))
import Cardano.Ledger.TxIn (TxId (..), TxIn (..))
import Cardano.Wallet.Tools.Ledger.Bundle
import Cardano.Wallet.Tools.Ledger.Envelope (TextEnvelope (..))
import Cardano.Wallet.Tools.Sign (DetachedWitness (..))
import Codec.Binary.Bech32 qualified as Bech32
import Control.Monad (unless)
import Data.Aeson (Value (..), eitherDecodeStrict, encode)
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Bifunctor (first)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.ByteString.Lazy qualified as BSL
import Data.Char (isSpace)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Maybe (fromMaybe)
import Data.Sequence.Strict qualified as StrictSeq
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Data.Word (Word32, Word64, Word8)
import Lens.Micro ((&), (.~), (^.))
import System.Directory (doesFileExist)
import System.FilePath ((</>))

-- | The ledger's transaction, as the library names it.
type ConwayTx = Tx TopTx ConwayEra

-- | The ledger's transaction body.
type ConwayTxBody = TxBody TopTx ConwayEra

-- * Fixtures

fixtureRoot :: FilePath
fixtureRoot = "test" </> "fixtures" </> "bundle"

-- | A bundle fixture's bytes; a missing file fails the example by name.
readBundleFixture :: FilePath -> IO ByteString
readBundleFixture name = do
    let path = fixtureRoot </> name
    present <- doesFileExist path
    unless present $
        fail $
            "fixture not found: "
                <> path
                <> " (the specs run from the package root)"
    BS.readFile path

-- | A hex fixture, decoded.
readBundleHexFixture :: FilePath -> IO ByteString
readBundleHexFixture name =
    readBundleFixture name
        >>= either fail pure . B16.decode . BC.filter (not . isSpace)

{- | The official unsigned-transaction envelope and the transaction the
ledger's own decoder reads from its CBOR.
-}
readOfficialTransaction :: IO (TextEnvelope, ConwayTx)
readOfficialTransaction = do
    envelope <- readBundleFixture "cardano-cli-tx-body.json"
    case eitherDecodeStrict envelope of
        Right (Object o)
            | Just (String kind) <- KeyMap.lookup "type" o
            , Just (String description) <- KeyMap.lookup "description" o
            , Just (String hex) <- KeyMap.lookup "cborHex" o -> do
                bytes <- either fail pure (B16.decode (TE.encodeUtf8 hex))
                pure (TextEnvelope kind description hex, txFromCbor bytes)
        other -> fail ("not an official envelope: " <> show other)

{- | The signing key a @cardano-cli@ payment signing-key envelope holds:
its @cborHex@ is a CBOR byte string of the 32-byte seed.
-}
readSigningKeyFixture :: FilePath -> IO (SignKeyDSIGN Ed25519DSIGN)
readSigningKeyFixture name = do
    envelope <- readBundleFixture name
    hex <- case eitherDecodeStrict envelope of
        Right (Object o) | Just (String h) <- KeyMap.lookup "cborHex" o -> pure h
        other -> fail ("not a key envelope: " <> show other)
    bytes <- either fail pure (B16.decode (TE.encodeUtf8 hex))
    unless (BS.take 2 bytes == BS.pack [0x58, 0x20]) $
        fail "the key envelope is not a 32-byte CBOR byte string"
    maybe (fail "not a signing key") pure $
        rawDeserialiseSignKeyDSIGN (BS.drop 2 bytes)

-- * Keys and addresses

{- | The RFC 8032 Ed25519 test vector 1 seed, the fixed test key whose
address the committed bundle fixture names among its signers.
-}
fixedKey :: SignKeyDSIGN Ed25519DSIGN
fixedKey =
    fromMaybe (error "Support.Ledger: the fixed key is not a signing key") $
        rawDeserialiseSignKeyDSIGN
            ( either
                (error "Support.Ledger: the fixed key is not hex")
                id
                ( B16.decode
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                )
            )

-- | A second deterministic key, distinct from the fixed one.
strangerKey :: SignKeyDSIGN Ed25519DSIGN
strangerKey =
    fromMaybe (error "Support.Ledger: the stranger key does not decode") $
        rawDeserialiseSignKeyDSIGN (BC.pack (replicate 31 's' <> "k"))

-- | A third deterministic key, distinct from the two above.
thirdKey :: SignKeyDSIGN Ed25519DSIGN
thirdKey =
    fromMaybe (error "Support.Ledger: the third key does not decode") $
        rawDeserialiseSignKeyDSIGN (BC.pack (replicate 31 't' <> "k"))

-- | A key from a byte pattern.
runtimeKey :: Word8 -> SignKeyDSIGN Ed25519DSIGN
runtimeKey firstByte =
    fromMaybe (error "Support.Ledger: the seed is not a signing key") $
        rawDeserialiseSignKeyDSIGN (BS.pack (firstByte : replicate 31 0x2a))

-- | The 32 bytes of a key's verification key.
verKeyBytes :: SignKeyDSIGN Ed25519DSIGN -> ByteString
verKeyBytes = rawSerialiseVerKeyDSIGN . deriveVerKeyDSIGN

-- | A signing key's hash in the role a body's required signers use.
requiredHashOf :: SignKeyDSIGN Ed25519DSIGN -> KeyHash Guard
requiredHashOf = hashKey . VKey . deriveVerKeyDSIGN

-- | The 28 bytes of a signing key's payment key hash.
keyHashBytes :: SignKeyDSIGN Ed25519DSIGN -> ByteString
keyHashBytes = hashToBytes . unKeyHash . requiredHashOf

-- | The enterprise address of a key on a test network.
addressOf :: SignKeyDSIGN Ed25519DSIGN -> Addr
addressOf key =
    Addr
        Testnet
        (KeyHashObj (hashKey (VKey (deriveVerKeyDSIGN key))))
        StakeRefNull

-- | An address as the bech32 text a bundle lists among its signers.
addressText :: Addr -> Text
addressText address =
    either (error . ("Support.Ledger: bech32: " <>)) id $ do
        hrp <- first show (Bech32.humanReadablePartFromText "addr_test")
        first
            show
            ( Bech32.encode
                hrp
                (Bech32.dataPartFromBytes (serialiseAddr address))
            )

{- | The fixed key's address on a test network, the signer of the
committed bundle fixture.
-}
fixedSigner :: Text
fixedSigner = addressText (addressOf fixedKey)

-- | The payment key hash an address carries.
paymentKeyHashOfAddress :: Addr -> ByteString
paymentKeyHashOfAddress = \case
    Addr _ (KeyHashObj hash) _ -> hashToBytes (unKeyHash hash)
    other -> error ("Support.Ledger: not a key address: " <> show other)

-- * Bodies and transactions

-- | The transaction that carries a body: the unsigned form.
txOf :: ConwayTxBody -> ConwayTx
txOf = mkBasicTx

{- | A synthetic Conway body with no inputs, no outputs and no required
signers, bounded by the slot given.
-}
syntheticBody :: Word64 -> ConwayTxBody
syntheticBody upper =
    mkBasicTxBody
        & vldtTxBodyL .~ ValidityInterval SNothing (SJust (SlotNo upper))

-- | The same synthetic body, requiring the key hashes given.
syntheticBodyRequiring
    :: Word64 -> Set (KeyHash Guard) -> ConwayTxBody
syntheticBodyRequiring upper hashes =
    syntheticBody upper & reqSignerHashesTxBodyL .~ hashes

-- | A body's validity upper bound, read as the deadline it is.
bodyDeadlineOf :: ConwayTxBody -> Maybe Word64
bodyDeadlineOf body = case body ^. vldtTxBodyL of
    ValidityInterval _ (SJust (SlotNo n)) -> Just n
    ValidityInterval _ SNothing -> Nothing

-- | A transaction's validity upper bound, read as the deadline it is.
deadlineOfTx :: ConwayTx -> Maybe Word64
deadlineOfTx tx = bodyDeadlineOf (tx ^. bodyTxL)

-- | The key hashes a transaction names as required signers.
requiredOf :: ConwayTx -> Set (KeyHash Guard)
requiredOf tx = tx ^. bodyTxL . reqSignerHashesTxBodyL

-- | A body spending the inputs given, paying one output to a key.
spendingBody
    :: SignKeyDSIGN Ed25519DSIGN
    -> [TxIn]
    -> Word64
    -> ConwayTxBody
spendingBody owner spent upper =
    mkBasicTxBody
        & inputsTxBodyL .~ Set.fromList spent
        & outputsTxBodyL
            .~ StrictSeq.singleton (paymentOutput (addressOf owner))
        & feeTxBodyL .~ Coin 1_000_000
        & vldtTxBodyL .~ ValidityInterval SNothing (SJust (SlotNo upper))

-- | A spending body with no validity upper bound.
unboundedBody :: SignKeyDSIGN Ed25519DSIGN -> TxIn -> ConwayTx
unboundedBody owner input =
    txOf
        ( spendingBody owner [input] 1000
            & vldtTxBodyL .~ ValidityInterval SNothing SNothing
        )

{- | Two chained transactions, the second spending the first's only
output, each paying the fixed key and bounded by the slot given.
-}
chainedPair :: Word64 -> (ConwayTx, ConwayTx)
chainedPair bound =
    let one = txOf (spendingBody fixedKey [funding 1] bound)
        two =
            txOf
                ( spendingBody
                    fixedKey
                    [TxIn (txIdTx one) (TxIx 0)]
                    bound
                )
    in  (one, two)

-- | The chained transactions as a list, in submission order.
chainedBodies :: Word64 -> [ConwayTx]
chainedBodies bound = [one, two]
  where
    (one, two) = chainedPair bound

-- | The n-th funding output reference, one the chain would hold.
funding :: Int -> TxIn
funding n =
    TxIn
        ( TxId
            ( unsafeMakeSafeHash
                ( fromMaybe
                    (error "Support.Ledger: not a 32-byte hash")
                    ( hashFromBytes
                        (BC.pack (replicate 31 'f' <> take 1 (show n)))
                    )
                )
            )
        )
        (TxIx 0)

-- | An output of two thousand ada paid to the address given.
paymentOutput :: Addr -> TxOut ConwayEra
paymentOutput address =
    mkBasicTxOut address (MaryValue (Coin 2_000_000_000) mempty)

-- | An output locked by a script credential.
scriptOutput :: Word8 -> TxOut ConwayEra
scriptOutput seed =
    mkBasicTxOut
        ( Addr
            Testnet
            ( ScriptHashObj
                ( ScriptHash
                    ( fromMaybe
                        (error "Support.Ledger: not a script hash")
                        (hashFromBytes (BS.replicate 28 seed))
                    )
                )
            )
            StakeRefNull
        )
        (MaryValue (Coin 2_000_000_000) mempty)

-- | The outputs of the bodies given, by the reference they would have.
outputsOfBodies :: [ConwayTx] -> [(TxIn, TxOut ConwayEra)]
outputsOfBodies bodies =
    [ (TxIn (txIdTx body) (TxIx (fromIntegral ix)), out)
    | body <- bodies
    , (ix, out) <-
        zip
            [0 :: Int ..]
            (foldr (:) [] (body ^. bodyTxL . outputsTxBodyL))
    ]

-- * Independent oracles

-- | The hash of a transaction's body as the ledger computes the id.
identityOf :: ConwayTx -> ByteString
identityOf tx = hashToBytes (extractHash h)
  where
    TxId h = txIdTx tx

{- | An independent blake2b-256 of the body's serialisation, computed
without the ledger's id.
-}
independentBodyHash :: ConwayTxBody -> ByteString
independentBodyHash body =
    hashToBytes
        ( hashWith @Blake2b_256
            id
            (BSL.toStrict (serialize (eraProtVerHigh @ConwayEra) body))
        )

{- | The envelope of an unsigned transaction as the official tool
spells it, built from the ledger's serialiser.
-}
envelopeOfTx :: ConwayTx -> TextEnvelope
envelopeOfTx tx =
    TextEnvelope
        { envelopeType = "Unwitnessed Tx ConwayEra"
        , envelopeDescription = "Ledger Cddl Format"
        , envelopeCborHex =
            hexTextOf (serialize' (eraProtVerHigh @ConwayEra) tx)
        }

{- | The detached witness of a key over a transaction: the key's
signature over the 32 identity bytes, by the signing primitive.
-}
witnessOver
    :: SignKeyDSIGN Ed25519DSIGN -> ConwayTx -> DetachedWitness
witnessOver key tx = witnessOverMessage key (identityOf tx)

-- | The detached witness of a key over any message.
witnessOverMessage
    :: SignKeyDSIGN Ed25519DSIGN -> ByteString -> DetachedWitness
witnessOverMessage key message =
    DetachedWitness
        { detachedWitnessVKey = verKeyBytes key
        , detachedWitnessSignature =
            rawSerialiseSigDSIGN (signDSIGN () message key)
        }

{- | The key witnesses a transaction carries, key and signature, read
from the ledger's own witness set.
-}
witnessesIn :: ConwayTx -> [DetachedWitness]
witnessesIn tx =
    [ DetachedWitness
        (rawSerialiseVerKeyDSIGN verKey)
        (rawSerialiseSigDSIGN signature)
    | WitVKey (VKey verKey) (SignedDSIGN signature) <-
        Set.toList (tx ^. witsTxL . addrTxWitsL)
    ]

-- | The serialisation of a transaction's body, as the ledger writes it.
bodyBytesOf :: ConwayTx -> ByteString
bodyBytesOf tx =
    BSL.toStrict (serialize (eraProtVerHigh @ConwayEra) (tx ^. bodyTxL))

{- | The raw CBOR of a detached witness as hex: a two-element array of
the key and signature byte strings.
-}
witnessCborHex :: DetachedWitness -> Text
witnessCborHex witness =
    hexTextOf $
        BS.concat
            [ BS.pack [0x82, 0x58, 0x20]
            , detachedWitnessVKey witness
            , BS.pack [0x58, 0x40]
            , detachedWitnessSignature witness
            ]

-- | The transaction a CBOR encoding carries, by the ledger's own decoder.
txFromCbor :: ByteString -> ConwayTx
txFromCbor bytes =
    either
        (error . ("Support.Ledger: not a transaction: " <>) . show)
        id
        ( decodeFullAnnotator
            (eraProtVerHigh @ConwayEra)
            "ConwayTx"
            decCBOR
            (BSL.fromStrict bytes)
        )

-- * Bundles

magic :: Word32
magic = 42

{- | One transaction of a bundle as an honest writer records it: the
body's true identity and deadline.
-}
bundleTxOf :: ConwayTx -> [Text] -> BundleTransaction
bundleTxOf tx effects =
    BundleTransaction
        { bundleTxIdentity = identityOf tx
        , bundleTxEnvelope = envelopeOfTx tx
        , bundleTxDeadline = deadlineOfTx tx
        , bundleTxEffects = effects
        }

{- | One transaction of a bundle with the identity, the deadline and the
envelope exactly as given.
-}
bundleTxRecording
    :: ByteString
    -> Maybe Word64
    -> TextEnvelope
    -> BundleTransaction
bundleTxRecording identity deadline envelope =
    BundleTransaction
        { bundleTxIdentity = identity
        , bundleTxEnvelope = envelope
        , bundleTxDeadline = deadline
        , bundleTxEffects = []
        }

{- | The sample bundle: more than one transaction, in submission order,
signed for by the fixed key.
-}
sampleBundle :: Bundle
sampleBundle =
    Bundle
        { bundleCommand = "registry fold"
        , bundleNetworkMagic = 1
        , bundleStateToken = Nothing
        , bundleSigners = fixedSigner :| []
        , bundleTransactions =
            bundleTxOf
                (txOf (syntheticBody 1000))
                ["returns the request's deposit to its owner"]
                :| [ bundleTxOf
                        (txOf (syntheticBody 1001))
                        ["pays the request's owner 2000000 lovelace"]
                   ]
        }

{- | A JSON document with a change applied to its top-level object, so a
spec tampers with the codec's own encoding without byte surgery.
-}
tamperJson
    :: (KeyMap Value -> KeyMap Value) -> ByteString -> ByteString
tamperJson change bytes = case eitherDecodeStrict bytes of
    Right (Object o) -> BSL.toStrict (encode (Object (change o)))
    other -> error ("Support.Ledger: not a JSON object: " <> show other)

{- | The bundle the committed fixture holds: the sample bundle as the
tool that wrote the fixture recorded it.
-}
fixtureBundle :: Bundle
fixtureBundle = sampleBundle{bundleCommand = "singular registry fold"}

-- | The bundle the planner rows plan: the transactions in order.
bundleOf :: [ConwayTx] -> Bundle
bundleOf txs =
    Bundle
        { bundleCommand = "registry fold"
        , bundleNetworkMagic = magic
        , bundleStateToken = Nothing
        , bundleSigners = fixedSigner :| []
        , bundleTransactions =
            case [ bundleTxOf
                    tx
                    ["claims to move " <> hexTextOf (identityOf tx) <> "'s funds"]
                 | tx <- txs
                 ] of
                [] -> error "Support.Ledger: a bundle needs transactions"
                t : ts -> t :| ts
        }

{- | The last byte of an identity flipped: a recorded identity that
disagrees with its body by construction.
-}
flippedIdentity :: ByteString -> ByteString
flippedIdentity bytes
    | BS.null bytes = bytes
    | otherwise = BS.init bytes <> BS.singleton (BS.last bytes `xor` 1)

-- | The first transaction of the sample bundle, replaced.
withFirst :: (BundleTransaction -> BundleTransaction) -> Bundle
withFirst replace = case bundleTransactions sampleBundle of
    t :| rest -> sampleBundle{bundleTransactions = replace t :| rest}

-- | Bytes as lowercase hex.
hexOf :: ByteString -> String
hexOf = BC.unpack . B16.encode

-- | Bytes as lowercase hex text.
hexTextOf :: ByteString -> Text
hexTextOf = TE.decodeUtf8 . B16.encode

-- | A transaction input's id in hex, as a refusal spells it.
txInHex :: TxIn -> String
txInHex (TxIn (TxId h) _) = hexOf (hashToBytes (extractHash h))
