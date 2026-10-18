{- |
Module      : Cardano.Wallet.Tools.Vault.BodyHashSpec
Description : A witness is a signature over the hash of the body
License     : Apache-2.0

A vkey witness signs blake2b-256 of the transaction body bytes, not the
body itself. The proofs compare what @cwt@ produces, byte for byte, with
the witness @cardano-cli@ made for the same key and body, and check
every signature under crypton's verification over the hash. The
expected witness and the keys come from fixture files read at run time;
the body bytes are taken out of the unsigned transaction fixture by the
library's own @transactionBodyBytes@, as @cwt sign@ does.
-}
module Cardano.Wallet.Tools.Vault.BodyHashSpec (spec) where

import Cardano.Wallet.Tools.Cli.Vault
    ( SigningKeySource (..)
    , loadSignerFromSource
    )
import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , Signer (..)
    , TxBodyBytes (..)
    , attachWitnesses
    , encodeDetachedWitness
    , transactionBodyBytes
    )
import Cardano.Wallet.Tools.Vault.Payload
    ( IdentitySelector (..)
    , OpenedKey (..)
    , parseSigningKeyEnvelope
    , signerFromKey
    )
import Cardano.Wallet.Tools.Vault.Scrypt (sealVault)
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text qualified as T
import Support.Vault
import System.FilePath ((</>))
import Test.Hspec
import Test.QuickCheck (forAll, ioProperty, property)
import Test.QuickCheck qualified as QC

spec :: Spec
spec = describe "vault v1" $ describe "witness body hash" $ do
    it "gives the cardano-cli witness for a plain signing key" $ do
        signer <- plainSigner "golden/payment.skey"
        expected <- readHexFixture "golden/witness.expected.hex"
        (rawWitness signer =<< goldenBody) `shouldReturn` expected

    it "gives the same witness from a v1 vault sealed by cwt" $
        withTempDir "bodyhash" $ \dir -> do
            skey <- readFixture "golden/payment.skey"
            key <- either (fail . show) pure (parseSigningKeyEnvelope skey)
            vault <-
                sealVault (factor 10) (passphrase "pass") key
                    >>= either (fail . show) pure
            let path = dir </> "payment.age"
            BS.writeFile path vault
            signer <- signerFromVaultFile path "pass" Nothing
            expected <- readHexFixture "golden/witness.expected.hex"
            (rawWitness signer =<< goldenBody) `shouldReturn` expected

    it "gives the same witness from a tx-sign cardano-cli identity" $ do
        payload <- readFixture "golden/cli.payload.json"
        [label] <- identityLabelsOfPayload payload
        secret <- readPassphraseFixture "golden/passphrase"
        signer <-
            signerFromVaultFile
                (fixturePath "golden/cli.vault.age")
                secret
                (Just (IdentitySelector label))
        expected <- readHexFixture "golden/witness.expected.hex"
        (rawWitness signer =<< goldenBody) `shouldReturn` expected

    it "attaches to the transaction cardano-cli signed, byte for byte" $ do
        signer <- plainSigner "golden/payment.skey"
        unsigned <- readHexFixture "golden/unsigned.cbor.hex"
        signed <- readHexFixture "golden/signed.expected.cbor.hex"
        witness <- signTxBody signer =<< goldenBody
        attachWitnesses [witness] unsigned `shouldBe` Right signed

    it "signs the hash of any body and not the body itself" $
        property $
            forAll ((,) <$> genSeed <*> genBody) $ \(seed, body) ->
                ioProperty $ do
                    witness <-
                        witnessOf
                            (signerFromKey (OpenedPlain (keyFromSeed seed)))
                            body
                    let vkey = detachedWitnessVKey witness
                        signature = detachedWitnessSignature witness
                    pure $
                        vkey == publicOf seed
                            && signatureVerifies vkey (bodyHash body) signature
                            && not (signatureVerifies vkey body signature)

    it "tells a signature over the body from one over its hash (control)" $ do
        let seed = seedKey 0x31
            body = "the transaction body bytes"
        secret <- case Ed25519.secretKey seed of
            CryptoPassed key -> pure key
            CryptoFailed e -> fail (show e)
        let public = Ed25519.toPublic secret
            over message = BA.convert (Ed25519.sign secret public message)
        signatureVerifies
            (publicOf seed)
            (bodyHash body)
            (over (bodyHash body))
            `shouldBe` True
        signatureVerifies (publicOf seed) body (over (bodyHash body))
            `shouldBe` False
        signatureVerifies (publicOf seed) body (over body)
            `shouldBe` True
        signatureVerifies (publicOf seed) (bodyHash body) (over body)
            `shouldBe` False
  where
    plainSigner name =
        loadSignerFromSource (PlaintextKey (fixturePath name))
            >>= either (fail . T.unpack) pure

-- | The body bytes of the golden unsigned transaction.
goldenBody :: IO TxBodyBytes
goldenBody =
    readHexFixture "golden/unsigned.cbor.hex"
        >>= either (fail . show) pure . transactionBodyBytes

-- | The witness a signer gives for a body, as the raw @[vkey, signature]@.
rawWitness :: Signer IO -> TxBodyBytes -> IO ByteString
rawWitness signer body = encodeDetachedWitness <$> signTxBody signer body

-- | A body of any size, empty included.
genBody :: QC.Gen ByteString
genBody = BS.pack <$> QC.listOf (QC.choose (0, 255))

-- | A 32-byte seed.
genSeed :: QC.Gen ByteString
genSeed = BS.pack <$> QC.vectorOf 32 (QC.choose (0, 255))
