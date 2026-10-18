{- |
Module      : Cardano.Wallet.Tools.Vault.Fido2InteropSpec
Description : A FIDO2 vault is an age file: stock age opens cwt's, cwt opens stock age's
License     : Apache-2.0

Both directions against stock @age@, in CI against the fake plugin and
on real hardware against @age-plugin-fido2-hmac@ (the operator's run).
Stock @age@ starts the plugin by name from the PATH, so it needs the
same directory of links the client uses; it speaks the plugin protocol
itself, which makes it a second client the fake plugin has to satisfy.
Expected values come from producers: the plaintext from stock @age@ and
the key from the @cardano-cli@ fixture pair, never from the code under
test.

These examples fail, never skip, when stock @age@ is not on the PATH.
-}
module Cardano.Wallet.Tools.Vault.Fido2InteropSpec (spec) where

import Cardano.Wallet.Tools.Vault.Fido2
import Cardano.Wallet.Tools.Vault.Payload (OpenedKey)
import Cardano.Wallet.Tools.Vault.Plugin
    ( openWithPlugins
    , parsePluginIdentity
    , parsePluginRecipient
    , refusingPluginUi
    , sealToPlugins
    )
import Control.Monad (forM, forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List.NonEmpty (NonEmpty (..))
import Data.List.NonEmpty qualified as NE
import Support.FakePlugin
import Support.Fido2
import Support.Vault
import System.Exit (ExitCode (..))
import Test.Hspec

spec :: Spec
spec = describe "fido2" $ describe "stock age" $ do
    cwtMadeVaults
    stockMadeVaults
    controls

pairs :: [String] -> IO (NonEmpty Keypair)
pairs labels = NE.fromList <$> forM labels (fakeKeypair "fido2-hmac")

-- | What stock age gave back for a vault, read as a cardano-cli envelope.
decryptedEnvelope :: ByteString -> IO Envelope
decryptedEnvelope plaintext = either fail pure (parseEnvelope plaintext)

cwtMadeVaults :: Spec
cwtMadeVaults = describe "a vault made by cwt" $ do
    it "decrypts under stock age -d -i to the cardano-cli signing key" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice"]
            key <- paymentKey
            vault <- sealedTo keys key
            (code, plaintext, err) <-
                ageDecryptWithIdentity (identityFileOf keys) vault
            (code, err) `shouldBe` (ExitSuccess, "")
            envelope <- decryptedEnvelope plaintext
            envelopeType envelope `shouldBe` "PaymentSigningKeyShelley_ed25519"
            original <-
                readFixture "payment.skey" >>= either fail pure . parseEnvelope
            envelopeCborHex envelope `shouldBe` envelopeCborHex original
            derived <- either fail pure (secretOfEnvelope envelope)
            expected <- verificationKeyOfFixture "payment.vkey"
            publicOf derived `shouldBe` expected

    it
        "decrypts under stock age with each identity of two recipients alone"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            keys <- pairs ["alice", "bob"]
            key <- paymentKey
            vault <- sealedTo keys key
            stanzaCountOf vault `shouldBe` Right 2
            forM_ (NE.toList keys) $ \pair -> do
                (code, plaintext, err) <-
                    ageDecryptWithIdentity (identityFileOf (pair :| [])) vault
                (code, err) `shouldBe` (ExitSuccess, "")
                envelope <- decryptedEnvelope plaintext
                original <-
                    readFixture "payment.skey" >>= either fail pure . parseEnvelope
                envelopeCborHex envelope `shouldBe` envelopeCborHex original

    it "decrypts a payload of several chunks under stock age" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            recipient <-
                maybe (fail "recipient") pure $
                    parsePluginRecipient (keypairRecipient alice)
            forM_ [65535, 65536, 65537, 200000] $ \size -> do
                let body = BS.pack (take size (cycle [0 .. 250]))
                vault <-
                    sealToPlugins refusingPluginUi (recipient :| []) body
                        >>= either (fail . show) pure
                (code, plaintext, err) <-
                    ageDecryptWithIdentity (identityFileOf (alice :| [])) vault
                (code, err) `shouldBe` (ExitSuccess, "")
                plaintext `shouldBe` body

stockMadeVaults :: Spec
stockMadeVaults = describe "a vault made by stock age" $ do
    it "opens with cwt, with each identity of two recipients alone" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            payload <- readFixture "payment.skey"
            vault <-
                ageEncryptToRecipients (keypairRecipient <$> NE.toList keys) payload
            stanzaCountOf vault `shouldBe` Right 2
            expected <- verificationKeyOfFixture "payment.vkey"
            forM_ (NE.toList keys) $ \pair -> do
                opened <- openedBy pair vault
                signsWith opened expected

    it "opens with cwt when made for one recipient" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["carol"]
            payload <- readFixture "payment.skey"
            vault <-
                ageEncryptToRecipients [keypairRecipient (NE.head keys)] payload
            expected <- verificationKeyOfFixture "payment.vkey"
            openedBy (NE.head keys) vault >>= (`signsWith` expected)

    it "is refused by cwt for an identity that is not a recipient" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            carol :| _ <- pairs ["carol"]
            payload <- readFixture "payment.skey"
            vault <-
                ageEncryptToRecipients (keypairRecipient <$> NE.toList keys) payload
            openedBy carol vault >>= (`shouldSatisfy` isNotOpened)
            -- control: an identity that is a recipient opens it
            expected <- verificationKeyOfFixture "payment.vkey"
            openedBy (NE.head keys) vault >>= (`signsWith` expected)

    it "opens, as plain age bytes, a payload of several chunks" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            identity <-
                maybe (fail "identity") pure $
                    parsePluginIdentity (keypairIdentity alice)
            forM_ [65535, 65536, 65537, 200000] $ \size -> do
                let body = BS.pack (take size (cycle [0 .. 250]))
                vault <- ageEncryptToRecipients [keypairRecipient alice] body
                openWithPlugins refusingPluginUi (identity :| []) vault
                    `shouldReturn` Right body

signsWith :: Either Fido2Refusal OpenedKey -> ByteString -> IO ()
signsWith opened expected = case opened of
    Left refusal -> fail ("expected the key, got " <> show refusal)
    Right key -> signsAs key expected

controls :: Spec
controls = describe "controls" $ do
    it
        "round-trips under stock age alone: the fake is a plugin to a real client"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            keys <- pairs ["alice", "bob"]
            payload <- readFixture "payment.skey"
            vault <-
                ageEncryptToRecipients (keypairRecipient <$> NE.toList keys) payload
            forM_ (NE.toList keys) $ \pair -> do
                (code, plaintext, err) <-
                    ageDecryptWithIdentity (identityFileOf (pair :| [])) vault
                (code, err) `shouldBe` (ExitSuccess, "")
                plaintext `shouldBe` payload

    it "is refused by stock age under another identity" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            bob :| _ <- pairs ["bob"]
            key <- paymentKey
            vault <- sealedTo (alice :| []) key
            (code, plaintext, _) <-
                ageDecryptWithIdentity (identityFileOf (bob :| [])) vault
            code `shouldNotBe` ExitSuccess
            plaintext `shouldBe` ""

    it "is refused by stock age for a vault changed at any byte" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            key <- paymentKey
            vault <- sealedTo (alice :| []) key
            let positions = [0, 13 .. BS.length vault - 1]
            length positions `shouldSatisfy` (> 10)
            forM_ positions $ \position -> do
                let changed = changedAt position vault
                (code, plaintext, _) <-
                    ageDecryptWithIdentity (identityFileOf (alice :| [])) changed
                code `shouldNotBe` ExitSuccess
                plaintext `shouldBe` ""
            -- the unchanged vault is opened by the same stock age
            (code, _, _) <-
                ageDecryptWithIdentity (identityFileOf (alice :| [])) vault
            code `shouldBe` ExitSuccess

    it "fails, never skips, when stock age is not on the PATH" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            key <- paymentKey
            vault <- sealedTo (alice :| []) key
            withPathOnly ["/nonexistent"] $
                ageDecryptWithIdentity (identityFileOf (alice :| [])) vault
                    `shouldThrow` anyException

    it "fails, never skips, when the fake plugin is not on the PATH" $
        withPathOnly ["/nonexistent"] fakePluginExecutable
            `shouldThrow` anyException
