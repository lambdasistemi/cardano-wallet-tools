{- |
Module      : Cardano.Wallet.Tools.Vault.InteropSpec
Description : A vault written by cwt opens with stock age
License     : Apache-2.0

The first acceptance line of the vault: a vault written by @cwt vault
seal@ decrypts with stock @age -d@ and yields a @cardano-cli@
signing-key envelope. Stock @cardano-cli@ is not available where this
runs, so "valid envelope" is the committed @cardano-cli@ fixture pair:
the key derived from the decrypted envelope must equal the fixture's
verification key, read from the @.vkey@ file at run time.

These examples fail, never skip, when stock @age@ is not on the PATH.
-}
module Cardano.Wallet.Tools.Vault.InteropSpec (spec) where

import Cardano.Wallet.Tools.Cli.Vault (runVaultSeal, vaultSealParser)
import Cardano.Wallet.Tools.Vault.Passphrase (Passphrase)
import Cardano.Wallet.Tools.Vault.Scrypt (sealVault)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Support.Vault
import System.Exit (ExitCode (..))
import System.FilePath ((</>))
import Test.Hspec
import Test.QuickCheck
    ( choose
    , forAll
    , ioProperty
    , property
    , withMaxSuccess
    )

spec :: Spec
spec = describe "vault v1" $
    describe "age interop" $ do
        it "opens, under stock age, a vault written by cwt vault seal" $
            withTempDir "interop" $ \dir -> do
                vault <- sealPayment dir ["--work-factor", "10"]
                (code, plaintext, err) <- ageDecrypt interopSecret vault
                (code, err) `shouldBe` (ExitSuccess, "")
                envelope <- either fail pure (parseEnvelope plaintext)
                envelopeType envelope
                    `shouldBe` "PaymentSigningKeyShelley_ed25519"
                derived <- either fail pure (secretOfEnvelope envelope)
                expected <- verificationKeyOfFixture "payment.vkey"
                publicOf derived `shouldBe` expected

        it "yields the very key the cardano-cli fixture holds" $
            withTempDir "interop" $ \dir -> do
                vault <- sealPayment dir ["--work-factor", "10"]
                (_, plaintext, _) <- ageDecrypt interopSecret vault
                sealedEnvelope <- either fail pure (parseEnvelope plaintext)
                original <-
                    readFixture "payment.skey" >>= either fail pure . parseEnvelope
                envelopeCborHex sealedEnvelope `shouldBe` envelopeCborHex original

        it "fails, never skips, when stock age is not on the PATH (control)" $
            withEnv [("PATH", "/nonexistent")] (ageDecrypt interopSecret "")
                `shouldThrow` anyException

        it "is refused by stock age under another passphrase (control)" $
            withTempDir "interop" $ \dir -> do
                vault <- sealPayment dir ["--work-factor", "10"]
                (code, plaintext, _) <- ageDecrypt "another passphrase" vault
                code `shouldNotBe` ExitSuccess
                plaintext `shouldBe` ""

        it "writes binary age with exactly one scrypt stanza" $
            withTempDir "interop" $ \dir -> do
                vault <- sealPayment dir ["--work-factor", "10"]
                vault `shouldSatisfy` BS.isPrefixOf "age-encryption.org/v1\n"
                vault
                    `shouldNotSatisfy` BS.isInfixOf "-----BEGIN AGE ENCRYPTED FILE-----"
                map scryptWorkFactorOf (headerStanzas vault) `shouldBe` [Just 10]

        it
            "reads the stanza count and work factor of a vault stock age made (control)"
            $ do
                stock <- readFixture "tx-sign/vault.age"
                map scryptWorkFactorOf (headerStanzas stock) `shouldBe` [Just 18]
                length
                    ( headerStanzas
                        "age-encryption.org/v1\n-> scrypt c2FsdA 10\nYm9keQ\n-> X25519 abc\nYm9keQ\n--- mac\n"
                    )
                    `shouldBe` 2

        it "records exactly the work factor it is given" $
            withMaxSuccess 12 $
                property $
                    forAll (choose (1, 12)) $ \n -> ioProperty $ do
                        vault <-
                            sealVault
                                (factor n)
                                interopPassphrase
                                (keyFromSeed (seedKey 0x51))
                                >>= either (fail . show) pure
                        pure $
                            map scryptWorkFactorOf (headerStanzas vault)
                                == [Just (fromIntegral n)]

        it "records the cap, 18, when no work factor is asked for" $
            withTempDir "interop" $ \dir -> do
                vault <- sealPayment dir []
                map scryptWorkFactorOf (headerStanzas vault) `shouldBe` [Just 18]

        it
            "seals the same key to different bytes each time, both opening under stock age"
            $ withTempDir "interop-first"
            $ \firstDir -> withTempDir "interop-second" $ \secondDir -> do
                first <- sealPayment firstDir ["--work-factor", "10"]
                second <- sealPayment secondDir ["--work-factor", "10"]
                first `shouldNotBe` second
                mapM_
                    ( \vault -> do
                        (code, _, _) <- ageDecrypt interopSecret vault
                        code `shouldBe` ExitSuccess
                    )
                    [first, second]

interopSecret :: ByteString
interopSecret = "cwt interop passphrase"

interopPassphrase :: Passphrase
interopPassphrase = passphrase interopSecret

{- | Seal the payment fixture key the way @cwt vault seal@ does, with the
passphrase on an inherited descriptor, and read the vault written.
-}
sealPayment :: FilePath -> [String] -> IO ByteString
sealPayment dir extra = do
    let out = dir </> "payment.age"
    withPassphraseDescriptor (interopSecret <> "\n") $ \fd -> do
        options <-
            either fail pure $
                parseArgs
                    vaultSealParser
                    ( [ "--signing-key"
                      , fixturePath "payment.skey"
                      , "--out"
                      , out
                      , "--passphrase-fd"
                      , show fd
                      ]
                        <> extra
                    )
        runVaultSeal options `shouldReturn` Right ()
    BS.readFile out
