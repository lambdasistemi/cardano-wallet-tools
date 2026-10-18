{-# LANGUAGE TypeApplications #-}

{- |
Module      : Cardano.Wallet.Tools.Ledger.WitnessSpec
Description : The ledger-typed detached witness and its assembly
License     : Apache-2.0

The signer is proved against the official tool: the fixture is the
witness @cardano-cli@ made for a signing key over a transaction, and the
library's witness for the same key and transaction must be that witness
byte for byte. The assembly is proved on the ledger's own witness set:
the body bytes and the identity stay, and exactly the witnesses given
are there.
-}
module Cardano.Wallet.Tools.Ledger.WitnessSpec (spec) where

import Cardano.Crypto.DSIGN
    ( Ed25519DSIGN
    , rawDeserialiseSigDSIGN
    , rawDeserialiseVerKeyDSIGN
    , verifyDSIGN
    )
import Cardano.Crypto.Hash (Blake2b_256, hashToBytes, hashWith)
import Cardano.Ledger.Api.Tx (bodyTxL)
import Cardano.Ledger.Binary (serialize')
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (eraProtVerHigh)
import Cardano.Wallet.Tools.Ledger.Witness
import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , TxBodyBytes (..)
    , encodeDetachedWitness
    , transactionBodyBytes
    )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Set qualified as Set
import Data.Word (Word8)
import Lens.Micro ((^.))
import Support.Ledger
import Test.Hspec
import Test.QuickCheck
    ( choose
    , forAll
    , property
    , (===)
    )

spec :: Spec
spec = describe "the ledger-typed detached witness" $ do
    theGolden
    theSigner
    theAssembly

-- * The golden witness

theGolden :: Spec
theGolden = describe "against the official tool" $ do
    it
        "signs the body hash and reproduces the official witness byte for byte"
        $ do
            key <- readSigningKeyFixture "golden/payment.skey"
            unsigned <- readBundleHexFixture "golden/unsigned.cbor.hex"
            expected <- readBundleHexFixture "golden/witness.expected.hex"
            let tx = txFromCbor unsigned
            encodeDetachedWitness (detachedWitness key tx) `shouldBe` expected
    it "signs the blake2b-256 of the body bytes the transaction carries" $ do
        key <- readSigningKeyFixture "golden/payment.skey"
        unsigned <- readBundleHexFixture "golden/unsigned.cbor.hex"
        TxBodyBytes body <-
            either (fail . show) pure (transactionBodyBytes unsigned)
        let witness = detachedWitness key (txFromCbor unsigned)
            digest = hashToBytes (hashWith @Blake2b_256 id body)
        signatureVerifies witness digest `shouldBe` True
    it "carries the key the official witness carries" $ do
        key <- readSigningKeyFixture "golden/payment.skey"
        unsigned <- readBundleHexFixture "golden/unsigned.cbor.hex"
        expected <- readBundleHexFixture "golden/witness.expected.hex"
        detachedWitnessVKey (detachedWitness key (txFromCbor unsigned))
            `shouldBe` BS.take 32 (BS.drop 3 expected)

-- | Whether the witness's signature verifies over the message.
signatureVerifies :: DetachedWitness -> ByteString -> Bool
signatureVerifies witness message =
    case ( rawDeserialiseVerKeyDSIGN (detachedWitnessVKey witness)
         , rawDeserialiseSigDSIGN @Ed25519DSIGN
            (detachedWitnessSignature witness)
         ) of
        (Just vk, Just sig) -> verifyDSIGN () vk message sig == Right ()
        _ -> False

-- * The signer

theSigner :: Spec
theSigner = describe "the signer" $ do
    let tx = txOf (syntheticBody 1000)
        witness = detachedWitness fixedKey tx
    it "carries the signer's public key" $
        detachedWitnessVKey witness `shouldBe` verKeyBytes fixedKey
    it "signs the body's hash, verifiably, and nothing else" $ do
        signatureVerifies witness (identityOf tx) `shouldBe` True
        signatureVerifies witness (independentBodyHash (syntheticBody 1000))
            `shouldBe` True
        signatureVerifies witness (BS.replicate 32 0) `shouldBe` False
        signatureVerifies witness (identityOf (txOf (syntheticBody 1001)))
            `shouldBe` False
    it "equals the witness a plain signature over the identity makes" $
        property $
            forAll (choose (0, 255 :: Word8)) $ \seed ->
                forAll (choose (0, 10 ^ (6 :: Int))) $ \bound ->
                    let key = runtimeKey seed
                        body = txOf (syntheticBody bound)
                    in  detachedWitness key body === witnessOver key body

-- * The assembly

{- | The complete witnesses of a body needing two keys, one over the
body's identity from each key.
-}
twoSignerBody :: ConwayTx
twoSignerBody =
    txOf
        ( syntheticBodyRequiring
            1000
            (Set.fromList [requiredHashOf fixedKey, requiredHashOf strangerKey])
        )

-- | A witness as the pair of its key and signature bytes.
pairOf :: DetachedWitness -> (ByteString, ByteString)
pairOf w = (detachedWitnessVKey w, detachedWitnessSignature w)

theAssembly :: Spec
theAssembly = describe "the assembly" $ do
    it
        "carries every verified witness of a body needing two keys, key and signature, and only those"
        $ do
            let body = twoSignerBody
                ws =
                    [ detachedWitness fixedKey body
                    , detachedWitness strangerKey body
                    ]
            witnessesIn (assembleWitnessed body ws) `shouldMatchList` ws
    it
        "carries every supplied witness whole, whatever their number above one"
        $ property
        $ forAll (choose (2, 5 :: Int))
        $ \count ->
            forAll (choose (0, 200 :: Word8)) $ \offset ->
                forAll (choose (0, 10 ^ (6 :: Int))) $ \bound ->
                    let tx = txOf (syntheticBody bound)
                        keys =
                            [ runtimeKey (offset + fromIntegral i)
                            | i <- [1 .. count]
                            ]
                        ws = [witnessOver key tx | key <- keys]
                        carried = witnessesIn (assembleWitnessed tx ws)
                    in  (length carried, Set.fromList (map pairOf carried))
                            === (count, Set.fromList (map pairOf ws))
    it
        "replaces, not keeps, the key witnesses the transaction already carries"
        $ do
            let body = twoSignerBody
                strangers = [detachedWitness strangerKey body]
                owners = [detachedWitness fixedKey body]
                preWitnessed = assembleWitnessed body strangers
                sealed = assembleWitnessed preWitnessed owners
            witnessesIn preWitnessed `shouldMatchList` strangers
            witnessesIn sealed `shouldMatchList` owners
            identityOf sealed `shouldBe` identityOf preWitnessed
    it "keeps the body bytes and identity, adding exactly the witnesses" $ do
        let (first, _) = chainedPair 1000
            ws = [detachedWitness fixedKey first]
            sealed = assembleWitnessed first ws
        identityOf sealed `shouldBe` identityOf first
        serialize' (eraProtVerHigh @ConwayEra) (sealed ^. bodyTxL)
            `shouldBe` serialize' (eraProtVerHigh @ConwayEra) (first ^. bodyTxL)
        witnessesIn sealed `shouldMatchList` ws
        witnessesIn first `shouldBe` []
    it "keeps each body's own witnesses apart across the bundle" $ do
        let (first, second) = chainedPair 1000
            wsFirst = [detachedWitness fixedKey first]
            wsSecond = [detachedWitness strangerKey second]
            sealedFirst = assembleWitnessed first wsFirst
            sealedSecond = assembleWitnessed second wsSecond
        witnessesIn sealedFirst `shouldMatchList` wsFirst
        witnessesIn sealedSecond `shouldMatchList` wsSecond
        identityOf sealedFirst `shouldBe` identityOf first
        identityOf sealedSecond `shouldBe` identityOf second
    it "assembles each body of the bundle with its own witnesses" $ do
        let bodies = chainedBodies 1000
            wsOf body = [detachedWitness fixedKey body]
            sealed = [assembleWitnessed body (wsOf body) | body <- bodies]
        map identityOf sealed `shouldBe` map identityOf bodies
        map witnessesIn sealed `shouldBe` map wsOf bodies
    it "adds nothing for bytes that are not a key and a signature" $ do
        let body = twoSignerBody
            nonsense = DetachedWitness "too-short" "also-short"
            good = detachedWitness fixedKey body
        witnessesIn (assembleWitnessed body [nonsense]) `shouldBe` []
        witnessesIn (assembleWitnessed body [nonsense, good])
            `shouldMatchList` [good]
    it
        "produces the same transaction bytes for the same witnesses in any order"
        $ do
            let body = twoSignerBody
                ws = [detachedWitness fixedKey body, detachedWitness strangerKey body]
            serialize' (eraProtVerHigh @ConwayEra) (assembleWitnessed body ws)
                `shouldBe` serialize'
                    (eraProtVerHigh @ConwayEra)
                    (assembleWitnessed body (reverse ws))
