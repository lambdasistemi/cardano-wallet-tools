{- |
Module      : Cardano.Wallet.Tools.Sign.WitnessSpec
Description : Golden tests for detached witness CBOR.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0
-}
module Cardano.Wallet.Tools.Sign.WitnessSpec
    ( spec
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Test.Hspec

import Cardano.Wallet.Tools.Sign.Witness

spec :: Spec
spec = describe "Cardano.Wallet.Tools.Sign.Witness" $ do
    it "decodes a raw detached vkey witness" $
        decodeDetachedWitness rawWitnessCbor `shouldBe` Right detachedWitness

    it "decodes a Shelley key-witness envelope" $
        decodeDetachedWitness envelopeWitnessCbor
            `shouldBe` Right detachedWitness

    it "encodes a raw detached vkey witness" $
        encodeDetachedWitness detachedWitness `shouldBe` rawWitnessCbor

    it "encodes a Shelley key-witness envelope" $
        encodeShelleyWitnessEnvelope detachedWitness
            `shouldBe` envelopeWitnessCbor

    it "round-trips encoded raw and envelope witnesses" $ do
        decodeDetachedWitness (encodeDetachedWitness detachedWitness)
            `shouldBe` Right detachedWitness
        decodeDetachedWitness (encodeShelleyWitnessEnvelope detachedWitness)
            `shouldBe` Right detachedWitness

    it "rejects non-vkey envelope tags" $
        decodeDetachedWitness unsupportedEnvelopeCbor
            `shouldBe` Left (WitnessEnvelopeTagUnsupported 1)

    it "rejects nested Shelley key-witness envelopes" $
        decodeDetachedWitness nestedEnvelopeCbor
            `shouldBe` Left WitnessDecodeExpectedByteString

detachedWitness :: DetachedWitness
detachedWitness =
    DetachedWitness
        { detachedWitnessVKey = vkeyBytes
        , detachedWitnessSignature = signatureBytes
        }

vkeyBytes :: ByteString
vkeyBytes = BS.pack [0 .. 31]

signatureBytes :: ByteString
signatureBytes = BS.pack [64 .. 127]

rawWitnessCbor :: ByteString
rawWitnessCbor =
    BS.concat
        [ BS.pack [0x82, 0x58, 0x20]
        , vkeyBytes
        , BS.pack [0x58, 0x40]
        , signatureBytes
        ]

envelopeWitnessCbor :: ByteString
envelopeWitnessCbor =
    BS.cons 0x82 (BS.cons 0x00 rawWitnessCbor)

unsupportedEnvelopeCbor :: ByteString
unsupportedEnvelopeCbor =
    BS.cons 0x82 (BS.cons 0x01 rawWitnessCbor)

nestedEnvelopeCbor :: ByteString
nestedEnvelopeCbor =
    BS.cons 0x82 (BS.cons 0x00 envelopeWitnessCbor)
