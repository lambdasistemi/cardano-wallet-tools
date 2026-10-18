{- |
Module      : Cardano.Wallet.Tools.Vault.ScryptSpec
Description : Sealing and opening a passphrase vault, and its work-factor cap
License     : Apache-2.0

The vault proofs: a sealed vault round-trips its key, every way a vault
can fail to open answers the one opening refusal, and a vault whose
work factor exceeds the cap is refused on every opening path. Vaults
above the cap and vaults with foreign plaintext are made here with the
age library directly, not with the seal under test.
-}
module Cardano.Wallet.Tools.Vault.ScryptSpec (spec) where

import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase (Passphrase)
import Cardano.Wallet.Tools.Vault.Payload
import Cardano.Wallet.Tools.Vault.Scrypt
import Control.Monad (forM, forM_)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.Text qualified as T
import Data.Word (Word8)
import Support.Vault
import Test.Hspec
import Test.QuickCheck
    ( choose
    , forAll
    , ioProperty
    , property
    , vectorOf
    , withMaxSuccess
    )

spec :: Spec
spec = describe "vault v1" $ do
    sealAndOpen
    workFactorCap

thePassphrase :: Passphrase
thePassphrase = passphrase "correct horse battery staple"

anotherPassphrase :: Passphrase
anotherPassphrase = passphrase "a deliberately wrong passphrase"

-- | The seal under test, unwrapped.
sealed :: Passphrase -> PaymentSigningKey -> IO ByteString
sealed = sealedAt 10

sealedAt :: Word8 -> Passphrase -> PaymentSigningKey -> IO ByteString
sealedAt n pass key =
    sealVault (factor n) pass key
        >>= either (fail . ("the seal refused: " <>) . show) pure

-- | Opened to the key it was sealed from, compared by the plaintext it writes.
opensTo
    :: PaymentSigningKey -> Either VaultRefusal OpenedKey -> Bool
opensTo key =
    either (const False) ((== Just (encodeV1Payload key)) . encodedV1Of)

sealAndOpen :: Spec
sealAndOpen = describe "seal and open" $ do
    it "round-trips the key at a cheap work factor" $ do
        let key = keyFromSeed (seedKey 0x31)
        bytes <- sealed thePassphrase key
        openVault Nothing thePassphrase bytes `shouldSatisfy` opensTo key

    it "round-trips any key at any cheap work factor" $
        withMaxSuccess 20 $
            property $
                forAll (vectorOf 32 (choose (0, 255))) $ \raw ->
                    forAll (choose (1, 4)) $ \n ->
                        let key = keyFromSeed (BS.pack raw)
                        in  ioProperty $ do
                                bytes <- sealedAt n thePassphrase key
                                pure $
                                    opensTo key $
                                        openVault Nothing thePassphrase bytes

    it "round-trips the key at the cap, work factor 18" $ do
        let key = keyFromSeed (seedKey 0x32)
        bytes <- sealedAt 18 thePassphrase key
        openVault Nothing thePassphrase bytes `shouldSatisfy` opensTo key

    it "refuses a wrong passphrase with the one opening refusal" $ do
        let key = keyFromSeed (seedKey 0x33)
        bytes <- sealed thePassphrase key
        openVault Nothing anotherPassphrase bytes
            `shouldSatisfy` either (== VaultNotOpened) (const False)

    it "refuses a corrupted vault, while the intact vault opens" $ do
        let key = keyFromSeed (seedKey 0x34)
        bytes <- sealed thePassphrase key
        let truncated = BS.init bytes
            bodyFlipped =
                BS.concat
                    [ BS.take 40 bytes
                    , BS.singleton (BS.index bytes 40 `xor` 1)
                    , BS.drop 41 bytes
                    ]
        openVault Nothing thePassphrase bytes `shouldSatisfy` opensTo key
        forM_ [truncated, bodyFlipped] $ \corrupt ->
            openVault Nothing thePassphrase corrupt
                `shouldSatisfy` either (== VaultNotOpened) (const False)

    it "refuses a file that is not a vault" $
        forM_ ["", "this is not a vault at all"] $ \bytes ->
            openVault Nothing thePassphrase bytes
                `shouldSatisfy` either (== VaultNotOpened) (const False)

    it "carries no key byte, key spelling or envelope in the clear" $ do
        let seed = "abcdefghijklmnopqrstuvwxyzABCDEF"
            key = keyFromSeed seed
        bytes <- sealed thePassphrase key
        bytes `shouldSatisfy` BS.isPrefixOf "age-encryption.org/v1"
        bytes `shouldNotSatisfy` BS.isInfixOf seed
        bytes `shouldNotSatisfy` BS.isInfixOf (B16.encode seed)
        bytes `shouldNotSatisfy` BS.isInfixOf "PaymentSigningKey"

    it "seals the same key twice to different bytes, both opening" $ do
        let key = keyFromSeed (seedKey 0x35)
        first <- sealed thePassphrase key
        second <- sealed thePassphrase key
        first `shouldNotBe` second
        forM_ [first, second] $ \bytes ->
            openVault Nothing thePassphrase bytes `shouldSatisfy` opensTo key

workFactorCap :: Spec
workFactorCap = describe "work factor cap" $ do
    it "is work factor 18" $
        vaultWorkFactorCap `shouldBe` factor 18

    context "a vault of the v1 format" $ do
        let key = keyFromSeed (seedKey 0x41)
            plaintext = encodeV1Payload key
        it "opens at the cap and below it" $
            forM_ [10, 18] $ \n -> do
                bytes <- encryptAtFactor n "pass" plaintext
                openVault Nothing (passphrase "pass") bytes
                    `shouldSatisfy` opensTo key
        it "is refused above the cap, with the right passphrase" $ do
            bytes <- encryptAtFactor 19 "pass" plaintext
            openVault Nothing (passphrase "pass") bytes
                `shouldSatisfy` either (== VaultNotOpened) (const False)

    context "a vault of the tx-sign format" $ do
        it "opens at a work factor within the cap, by label" $ do
            payload <- readFixture "tx-sign/payload.json"
            vkey <- verificationKeyOfFixture "tx-sign/alice.vkey"
            bytes <- encryptAtFactor 10 "pass" payload
            case openVault (Just (IdentitySelector "alice")) (passphrase "pass") bytes of
                Right key -> signsAs key vkey
                Left refusal -> expectationFailure (show refusal)
        it "is refused above the cap, for every identity choice" $ do
            payload <- readFixture "tx-sign/payload.json"
            bytes <- encryptAtFactor 19 "pass" payload
            forM_ [Nothing, Just (IdentitySelector "alice")] $ \selector ->
                openVault selector (passphrase "pass") bytes
                    `shouldSatisfy` either (== VaultNotOpened) (const False)

    it "answers one refusal, with one rendering, for every way to fail" $ do
        let key = keyFromSeed (seedKey 0x42)
            right = passphrase "pass"
        intact <- encryptAtFactor 10 "pass" (encodeV1Payload key)
        aboveCap <- encryptAtFactor 19 "pass" (encodeV1Payload key)
        vkeyFixture <- readFixture "payment.vkey"
        notAKey <- forM
            ( [ ("text", "hello")
              , ("a verification key", vkeyFixture)
              , ("a stake key", stakeEnvelope)
              ]
                :: [(String, ByteString)]
            )
            $ \(what, plaintext) -> (,) what <$> encryptAtFactor 10 "pass" plaintext
        versionTwo <- encryptAtFactor 10 "pass" (BC.pack versionTwoPayload)
        let failing :: [(String, Passphrase, ByteString)]
            failing =
                [ ("wrong passphrase", anotherPassphrase, intact)
                , ("truncated", right, BS.init intact)
                , ("not a vault", right, "not a vault")
                , ("above the cap", right, aboveCap)
                , ("tx-sign version 2", right, versionTwo)
                ]
                    <> [(what, right, bytes) | (what, bytes) <- notAKey]
        openVault Nothing right intact `shouldSatisfy` opensTo key
        forM_ failing $ \(what, pass, bytes) ->
            (what, openVault Nothing pass bytes)
                `shouldSatisfy` (either (== VaultNotOpened) (const False) . snd)
        renderVaultRefusal VaultNotOpened `shouldSatisfy` (not . T.null)
  where
    stakeEnvelope =
        "{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"spec\",\"cborHex\":\"5820"
            <> B16.encode (seedKey 0x42)
            <> "\"}"
    versionTwoPayload =
        "{\"cardanoTxSignVault\":{\"version\":2,\"identities\":{}}}"
