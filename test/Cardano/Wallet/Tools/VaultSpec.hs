module Cardano.Wallet.Tools.VaultSpec (spec) where

import Cardano.Wallet.Tools.Vault
import Data.ByteString qualified as BS
import Test.Hspec
import Test.QuickCheck (ioProperty, property)

-- | Fast work factor for tests — N = 2^1 = 2 scrypt iterations.
fastWF :: WorkFactor
fastWF = case mkWorkFactor 1 of
    Just wf -> wf
    Nothing -> error "VaultSpec.fastWF: impossible"

spec :: Spec
spec = describe "Cardano.Wallet.Tools.Vault" $ do
    describe "mkVaultPassphrase" $ do
        it "rejects an empty passphrase" $
            mkVaultPassphrase BS.empty `shouldBe` Left VaultEmptyPassphrase

        it "accepts a non-empty passphrase" $
            mkVaultPassphrase "hunter2" `shouldSatisfy` isRight

    describe "encryptVault / decryptVault" $ do
        it "round-trips a known payload" $ do
            pp <- expectRight $ mkVaultPassphrase "correct horse battery staple"
            cipher <- encryptVault fastWF pp "hello age" >>= expectRight
            decryptVault pp cipher `shouldBe` Right "hello age"

        it "each encryption produces a different ciphertext (random salt)" $ do
            pp <- expectRight $ mkVaultPassphrase "same"
            c1 <- encryptVault fastWF pp "payload" >>= expectRight
            c2 <- encryptVault fastWF pp "payload" >>= expectRight
            c1 `shouldNotBe` c2

        it "returns VaultDecryptError on wrong passphrase" $ do
            pp1 <- expectRight $ mkVaultPassphrase "right"
            pp2 <- expectRight $ mkVaultPassphrase "wrong"
            cipher <- encryptVault fastWF pp1 "secret" >>= expectRight
            decryptVault pp2 cipher `shouldBe` Left VaultDecryptError

        it "round-trips arbitrary ByteString payloads" $
            property $
                \(bytes :: [Int]) ->
                    ioProperty $ do
                        let payload = BS.pack (map fromIntegral bytes)
                        pp <- expectRight $ mkVaultPassphrase "prop-test"
                        cipher <-
                            encryptVault fastWF pp payload >>= expectRight
                        pure (decryptVault pp cipher == Right payload)

-- ---------------------------------------------------------------------------
-- Helpers

isRight :: Either a b -> Bool
isRight = either (const False) (const True)

expectRight :: Either VaultError a -> IO a
expectRight (Right x) = pure x
expectRight (Left e) = fail $ "expected Right, got: " <> show e
