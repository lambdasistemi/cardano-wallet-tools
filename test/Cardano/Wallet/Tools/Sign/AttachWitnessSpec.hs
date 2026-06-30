{- |
Module      : Cardano.Wallet.Tools.Sign.AttachWitnessSpec
Description : Body-preserving witness attachment tests.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0
-}
module Cardano.Wallet.Tools.Sign.AttachWitnessSpec
    ( spec
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Test.Hspec
import Test.QuickCheck

import Cardano.Wallet.Tools.Sign.AttachWitness
import Cardano.Wallet.Tools.Sign.Witness

spec :: Spec
spec = describe "Cardano.Wallet.Tools.Sign.AttachWitness" $ do
    it "extracts the exact first array element bytes" $
        transactionBodyBytes (txWith bodyTerm emptyWitnessSet)
            `shouldBe` Right (TxBodyBytes bodyTerm)

    it
        "attaches one witness to an empty witness set without changing the body"
        $ do
            let tx = txWith bodyTerm emptyWitnessSet
                expectedWitnessSet =
                    BS.concat
                        [ BS.pack [0xa1, 0x00]
                        , taggedWitnessSet [rawWitnessCbor]
                        ]
                expected = txWith bodyTerm expectedWitnessSet

            attachWitnesses [detachedWitness] tx `shouldBe` Right expected
            transactionBodyBytes expected `shouldBe` Right (TxBodyBytes bodyTerm)

    it "preserves a non-vkey witness-set field while attaching" $ do
        let otherField = BS.pack [0x02, 0x43, 0xde, 0xad, 0xbe]
            tx = txWith bodyTerm (BS.cons 0xa1 otherField)
            expectedWitnessSet =
                BS.concat
                    [ BS.pack [0xa2]
                    , otherField
                    , BS.pack [0x00]
                    , taggedWitnessSet [rawWitnessCbor]
                    ]

        attachWitnesses [detachedWitness] tx
            `shouldBe` Right (txWith bodyTerm expectedWitnessSet)

    it "appends to an existing key 0 tagged witness set" $ do
        let tx =
                txWith
                    bodyTerm
                    ( BS.concat
                        [ BS.pack [0xa1, 0x00]
                        , taggedWitnessSet [secondRawWitnessCbor]
                        ]
                    )
            expectedWitnessSet =
                BS.concat
                    [ BS.pack [0xa1, 0x00]
                    , taggedWitnessSet [secondRawWitnessCbor, rawWitnessCbor]
                    ]

        attachWitnesses [detachedWitness] tx
            `shouldBe` Right (txWith bodyTerm expectedWitnessSet)

    it
        "preserves the extracted body bytes for generated small CBOR body terms"
        $ property
        $ \(SmallBodyTerm generatedBody) ->
            let tx = txWith generatedBody emptyWitnessSet
            in  case attachWitnesses [detachedWitness] tx of
                    Right attachedTx ->
                        transactionBodyBytes tx
                            === transactionBodyBytes attachedTx
                    Left _ ->
                        property False

bodyTerm :: ByteString
bodyTerm =
    BS.pack
        [ 0xa2
        , 0x00
        , 0x81
        , 0x01
        , 0x01
        , 0x43
        , 0x10
        , 0x20
        , 0x30
        ]

emptyWitnessSet :: ByteString
emptyWitnessSet = BS.singleton 0xa0

txWith :: ByteString -> ByteString -> ByteString
txWith body witnessSet =
    BS.concat
        [ BS.singleton 0x84
        , body
        , witnessSet
        , BS.pack [0xf5, 0xf6]
        ]

taggedWitnessSet :: [ByteString] -> ByteString
taggedWitnessSet witnesses =
    BS.concat
        [ BS.pack [0xd9, 0x01, 0x02]
        , encodeArrayLength (length witnesses)
        , BS.concat witnesses
        ]

encodeArrayLength :: Int -> ByteString
encodeArrayLength len
    | len < 24 = BS.singleton (0x80 + fromIntegral len)
    | otherwise = error "test witness arrays are intentionally tiny"

detachedWitness :: DetachedWitness
detachedWitness =
    DetachedWitness
        { detachedWitnessVKey = BS.pack [0 .. 31]
        , detachedWitnessSignature = BS.pack [64 .. 127]
        }

secondDetachedWitness :: DetachedWitness
secondDetachedWitness =
    DetachedWitness
        { detachedWitnessVKey = BS.pack [1 .. 32]
        , detachedWitnessSignature = BS.pack [65 .. 128]
        }

rawWitnessCbor :: ByteString
rawWitnessCbor = encodeDetachedWitness detachedWitness

secondRawWitnessCbor :: ByteString
secondRawWitnessCbor = encodeDetachedWitness secondDetachedWitness

newtype SmallBodyTerm = SmallBodyTerm ByteString
    deriving stock (Show)

instance Arbitrary SmallBodyTerm where
    arbitrary =
        SmallBodyTerm <$> sized (genTerm . min 4)

genTerm :: Int -> Gen ByteString
genTerm depth =
    oneof (scalarTerms <> nestedTerms)
  where
    scalarTerms =
        [ genUnsigned
        , genBytes
        , genText
        , pure (BS.singleton 0xf4)
        , pure (BS.singleton 0xf5)
        , pure (BS.singleton 0xf6)
        ]
    nestedTerms
        | depth > 0 = [genArray depth, genMap depth]
        | otherwise = []

genUnsigned :: Gen ByteString
genUnsigned =
    encodeSmallUnsigned <$> chooseInt (0, 23)

genBytes :: Gen ByteString
genBytes = do
    len <- chooseInt (0, 12)
    bytes <- BS.pack <$> vectorOf len (chooseEnum (0, 10))
    pure (BS.cons (0x40 + fromIntegral (BS.length bytes)) bytes)

genText :: Gen ByteString
genText = do
    len <- chooseInt (0, 12)
    chars <- vectorOf len (elements [0x61 .. 0x7a])
    let bytes = BS.pack chars
    pure (BS.cons (0x60 + fromIntegral (BS.length bytes)) bytes)

genArray :: Int -> Gen ByteString
genArray depth = do
    len <- chooseInt (0, 3)
    terms <- vectorOf len (genTerm (depth - 1))
    pure (BS.cons (0x80 + fromIntegral len) (BS.concat terms))

genMap :: Int -> Gen ByteString
genMap depth = do
    len <- chooseInt (0, 3)
    entries <-
        vectorOf len ((,) <$> genTerm (depth - 1) <*> genTerm (depth - 1))
    pure $
        BS.cons (0xa0 + fromIntegral len) $
            BS.concat [key <> value | (key, value) <- entries]

encodeSmallUnsigned :: Int -> ByteString
encodeSmallUnsigned value = BS.singleton (fromIntegral value)
