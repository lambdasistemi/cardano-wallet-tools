{-# LANGUAGE TypeApplications #-}

{- |
Module      : Cardano.Wallet.Tools.Ledger.EnvelopeSpec
Description : cardano-cli text envelopes of transactions and witnesses
License     : Apache-2.0

The envelopes are checked against the official tool's own output: the
files are what @cardano-cli@ wrote, and the specs prove them in both
directions. What the official tool wrote reads, and writing what was
read reproduces its bytes; what this library writes for a transaction
is the ledger's serialisation, and what it writes for a witness is the
official spelling of one.
-}
module Cardano.Wallet.Tools.Ledger.EnvelopeSpec (spec) where

import Cardano.Ledger.Binary (serialize')
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (eraProtVerHigh)
import Cardano.Wallet.Tools.Ledger.Envelope
import Cardano.Wallet.Tools.Sign (DetachedWitness (..))
import Data.Aeson (Value (..), eitherDecodeStrict)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Support.Ledger
import Test.Hspec
import Test.QuickCheck
    ( Gen
    , choose
    , forAll
    , property
    , vectorOf
    , (===)
    )

spec :: Spec
spec = describe "the text envelopes" $ do
    theTransactionEnvelope
    theOfficialTransaction
    theWitnessEnvelope
    theOfficialWitness

-- | A text envelope as the official tool's file spells it.
officialEnvelope :: FilePath -> IO TextEnvelope
officialEnvelope name = do
    bytes <- readBundleFixture name
    either
        (fail . ("the official envelope is not one: " <>) . show)
        pure
        (decodeTextEnvelope bytes)

hexBytes :: Text -> ByteString
hexBytes = either error id . B16.decode . TE.encodeUtf8

genBytes :: Int -> Gen ByteString
genBytes n = BS.pack <$> vectorOf n (choose (0, 255))

genWitness :: Gen DetachedWitness
genWitness = DetachedWitness <$> genBytes 32 <*> genBytes 64

-- * The unsigned transaction

theTransactionEnvelope :: Spec
theTransactionEnvelope = describe "an unsigned transaction" $ do
    it
        "is written as the unwitnessed Conway envelope of the ledger's bytes"
        $ do
            let tx = txOf (syntheticBody 1000)
                envelope = transactionEnvelope tx
            envelopeType envelope `shouldBe` "Unwitnessed Tx ConwayEra"
            envelopeDescription envelope `shouldBe` "Ledger Cddl Format"
            envelope `shouldBe` envelopeOfTx tx
    it "decodes what it writes, transaction for transaction" $ do
        let tx = txOf (syntheticBody 1000)
        decodeTransactionEnvelope (transactionEnvelope tx) `shouldBe` Right tx
    it "refuses a bare body, which is not a transaction" $ do
        let bareBody =
                TextEnvelope
                    { envelopeType = transactionEnvelopeType
                    , envelopeDescription = "Ledger Cddl Format"
                    , envelopeCborHex =
                        hexTextOf
                            (serialize' (eraProtVerHigh @ConwayEra) (syntheticBody 1000))
                    }
        case decodeTransactionEnvelope bareBody of
            Left _ -> pure ()
            Right decoded ->
                expectationFailure ("a bare body decoded: " <> show decoded)
    it "refuses a cborHex that is not hex" $
        case decodeTransactionEnvelope
            (envelopeOfTx (txOf (syntheticBody 1000))){envelopeCborHex = "xyz"} of
            Left _ -> pure ()
            Right decoded ->
                expectationFailure ("non-hex decoded: " <> show decoded)
    it "reads both labels the official tools use" $ do
        let tx = txOf (syntheticBody 1000)
        mapM_
            ( \label ->
                decodeTransactionEnvelope
                    (transactionEnvelope tx){envelopeType = label}
                    `shouldBe` Right tx
            )
            acceptedTransactionEnvelopeTypes
        acceptedTransactionEnvelopeTypes
            `shouldBe` [transactionEnvelopeType, "Tx ConwayEra"]

theOfficialTransaction :: Spec
theOfficialTransaction = describe "the official unsigned transaction" $ do
    it "reads, and writing it back reproduces its bytes" $ do
        official <- officialEnvelope "cardano-cli-tx-body.json"
        decoded <- case decodeTransactionEnvelope official of
            Right tx -> pure tx
            Left why -> fail ("official envelope refused: " <> why)
        let written = transactionEnvelope decoded
        envelopeCborHex written `shouldBe` envelopeCborHex official
        envelopeDescription written `shouldBe` envelopeDescription official
    it "carries a label this library reads" $ do
        official <- officialEnvelope "cardano-cli-tx-body.json"
        envelopeType official
            `shouldSatisfy` (`elem` acceptedTransactionEnvelopeTypes)

-- * The detached witness

theWitnessEnvelope :: Spec
theWitnessEnvelope = describe "a detached witness" $ do
    it "round-trips through its envelope file, whatever the bytes" $
        property $
            forAll genWitness $ \witness ->
                decodeWitnessEnvelope (encodeTextEnvelope (witnessEnvelope witness))
                    === Right witness
    it "is written typed and described as the official tool writes one" $
        do
            let envelope =
                    witnessEnvelope (witnessOver fixedKey (txOf (syntheticBody 1000)))
            envelopeType envelope `shouldBe` "TxWitness ConwayEra"
            envelopeDescription envelope `shouldBe` "Key Witness ShelleyEra"
    it "carries the raw array of the key and the signature" $ do
        let witness = witnessOver fixedKey (txOf (syntheticBody 1000))
        envelopeCborHex (witnessEnvelope witness)
            `shouldBe` witnessCborHex witness
    it "writes JSON with the three envelope fields" $ do
        let witness = witnessOver fixedKey (txOf (syntheticBody 1000))
        case eitherDecodeStrict (encodeTextEnvelope (witnessEnvelope witness)) of
            Right (Object o) -> do
                KeyMap.lookup "type" o `shouldBe` Just (String "TxWitness ConwayEra")
                KeyMap.lookup "description" o
                    `shouldBe` Just (String "Key Witness ShelleyEra")
                KeyMap.lookup "cborHex" o
                    `shouldBe` Just (String (witnessCborHex witness))
            other -> expectationFailure ("not an envelope object: " <> show other)
    it "refuses an envelope of another type" $ do
        let wrongType =
                (witnessEnvelope (witnessOver fixedKey (txOf (syntheticBody 1000))))
                    { envelopeType = "Tx ConwayEra"
                    }
        decodeWitnessEnvelope (encodeTextEnvelope wrongType)
            `shouldBe` Left (EnvelopeWrongType "Tx ConwayEra")
    it "refuses an envelope whose CBOR is not a key witness" $ do
        let short = DetachedWitness "too-short" "also-short"
        case decodeWitnessEnvelope (encodeTextEnvelope (witnessEnvelope short)) of
            Left (EnvelopeField "witness" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses bytes that are not JSON" $
        case decodeWitnessEnvelope "not json" of
            Left (EnvelopeField _ _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses a witness whose cborHex is not hex" $ do
        let notHex =
                (witnessEnvelope (witnessOver fixedKey (txOf (syntheticBody 1000))))
                    { envelopeCborHex = "xyz"
                    }
        case decodeWitnessEnvelope (encodeTextEnvelope notHex) of
            Left (EnvelopeField _ _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)

theOfficialWitness :: Spec
theOfficialWitness = describe "the official witness" $ do
    it "reads as the key and signature its CBOR carries" $ do
        bytes <- readBundleFixture "cardano-cli-tx-witness.json"
        official <- officialEnvelope "cardano-cli-tx-witness.json"
        let raw = hexBytes (envelopeCborHex official)
            -- 0x82, bytes(32), bytes(64)
            key = BS.take 32 (BS.drop 3 raw)
            signature = BS.take 64 (BS.drop 37 raw)
        decodeWitnessEnvelope bytes
            `shouldBe` Right
                DetachedWitness
                    { detachedWitnessVKey = key
                    , detachedWitnessSignature = signature
                    }
    it "is reproduced field for field when written back" $ do
        bytes <- readBundleFixture "cardano-cli-tx-witness.json"
        official <- officialEnvelope "cardano-cli-tx-witness.json"
        witness <-
            either
                (fail . renderEnvelopeRefusal)
                pure
                (decodeWitnessEnvelope bytes)
        witnessEnvelope witness `shouldBe` official
        BC.length (encodeTextEnvelope (witnessEnvelope witness))
            `shouldSatisfy` (> 0)
