{- |
Module      : Cardano.Wallet.Tools.Vault.Fido2Spec
Description : The FIDO2 vault kind: shape, opening, refusals, rekeying
License     : Apache-2.0

A FIDO2 vault is a standard binary age v1 file whose every stanza was
wrapped by a @fido2-hmac@ plugin and whose plaintext is the vault v1
payload. The plugin here is the fake one, a real child process on the
specs' own PATH. Every expected value is obtained from a producer at
run time: key pairs from the fake, the key's v1 plaintext from the
library's own writer applied to a key made from a seed, stanza tags
from the age library's header parser.
-}
module Cardano.Wallet.Tools.Vault.Fido2Spec (spec) where

import Cardano.Wallet.Tools.Vault.Fido2
import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Payload (encodeV1Payload)
import Cardano.Wallet.Tools.Vault.Plugin
    ( parsePluginRecipient
    , refusingPluginUi
    , sealToPlugins
    )
import Cardano.Wallet.Tools.Vault.Scrypt (sealVault)
import Control.Monad (forM, forM_)
import Data.ByteString qualified as BS
import Data.Either (isRight)
import Data.List.NonEmpty (NonEmpty (..))
import Data.List.NonEmpty qualified as NE
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.FakePlugin
import Support.Fido2
import Support.Vault (factor, passphrase)
import Test.Hspec
import Test.QuickCheck
    ( choose
    , forAll
    , ioProperty
    , property
    , withMaxSuccess
    )

spec :: Spec
spec = do
    describe "fido2" $ describe "protocol" $ do
        recipientsAndIdentities
        vaultShape
        openRefusals
    describe "fido2" $ do
        twoRecipients
        rekey

pairs :: [String] -> IO (NonEmpty Keypair)
pairs labels =
    NE.fromList <$> forM labels (fakeKeypair "fido2-hmac")

recipientsAndIdentities :: Spec
recipientsAndIdentities = describe "recipients and identities" $ do
    it "reads a fido2-hmac recipient" $ do
        pair <- fakeKeypair "fido2-hmac" "alice"
        fmap fido2RecipientText (parseFido2Recipient (keypairRecipient pair))
            `shouldBe` Right (keypairRecipient pair)

    it "refuses a recipient that is not a fido2-hmac recipient" $ do
        alice <- fakeKeypair "fido2-hmac" "alice"
        parseFido2Recipient (keypairRecipient alice) `shouldSatisfy` isRight
        other <- fakeKeypair "fake-other" "alice"
        forM_
            [ keypairRecipient other
            , "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
            , "not a recipient"
            , ""
            ]
            $ \text ->
                parseFido2Recipient text
                    `shouldBe` Left (NotAFido2Recipient text)

    it "reads the identities of a file, ignoring comments and blank lines" $ do
        alice <- fakeKeypair "fido2-hmac" "alice"
        bob <- fakeKeypair "fido2-hmac" "bob"
        let file =
                "# written for the specs\n\n"
                    <> TE.encodeUtf8 (keypairIdentity alice)
                    <> "\r\n  \n# another\n"
                    <> TE.encodeUtf8 (keypairIdentity bob)
        fmap NE.length (parseFido2Identities file) `shouldBe` Right 2

    it "refuses an identity file with no identity, or another plugin's" $ do
        alice <- fakeKeypair "fido2-hmac" "alice"
        parseFido2Identities (TE.encodeUtf8 (keypairIdentity alice))
            `shouldSatisfy` isRight
        other <- fakeKeypair "fake-other" "alice"
        forM_
            [ ""
            , "# only a comment\n"
            , "\n\n"
            , TE.encodeUtf8 (keypairIdentity other)
            , "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"
            ]
            $ \file ->
                fmap NE.length (parseFido2Identities file)
                    `shouldBe` Left NotAFido2Identity

    it "refuses an identity file of which one line is not fido2-hmac" $ do
        alice <- fakeKeypair "fido2-hmac" "alice"
        other <- fakeKeypair "fake-other" "alice"
        parseFido2Identities (TE.encodeUtf8 (keypairIdentity alice))
            `shouldSatisfy` isRight
        parseFido2Identities
            ( TE.encodeUtf8 (keypairIdentity alice)
                <> "\n"
                <> TE.encodeUtf8 (keypairIdentity other)
            )
            `shouldSatisfy` either (== NotAFido2Identity) (const False)

    it "shows no identity" $ do
        alice <- fakeKeypair "fido2-hmac" "alice"
        let shown = show (identitiesOf (alice :| []))
        shown
            `shouldSatisfy` (not . (T.unpack (keypairIdentity alice) `isInfixOfS`))
  where
    isInfixOfS needle haystack = T.pack needle `T.isInfixOf` T.pack haystack

vaultShape :: Spec
vaultShape = describe "vault shape" $ do
    it "is a binary age v1 file with one fido2-hmac stanza per recipient" $
        withFakePlugins ["fido2-hmac"] $
            forM_ [1, 2, 3] $ \n -> do
                keys <- pairs (take n ["alice", "bob", "carol"])
                vault <- sealedTo keys (plainKey (0x41 :: Int))
                vault `shouldSatisfy` BS.isPrefixOf "age-encryption.org/v1\n"
                vault
                    `shouldNotSatisfy` BS.isInfixOf "-----BEGIN AGE ENCRYPTED FILE-----"
                stanzaTagsOf vault `shouldBe` Right (replicate n "fido2-hmac")

    it "has no scrypt stanza and no stanza of another kind" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            vault <- sealedTo keys (plainKey (0x42 :: Int))
            stanzaTagsOf vault
                `shouldSatisfy` either (const False) (all (== "fido2-hmac"))
            vault `shouldSatisfy` (not . BS.isInfixOf "-> scrypt")
            vault `shouldSatisfy` (not . BS.isInfixOf "-> X25519")

    it "counts a recipient given twice once" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| [bob] <- pairs ["alice", "bob"]
            let recipients =
                    recipientsOf (alice :| [bob, alice, bob, alice])
            vault <-
                sealFido2Vault refusingPluginUi recipients (plainKey (0x43 :: Int))
                    >>= either (fail . show) pure
            stanzaTagsOf vault `shouldBe` Right ["fido2-hmac", "fido2-hmac"]

    it
        "holds the v1 payload: the key a fido2 identity opens is the sealed key"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            alice :| _ <- pairs ["alice"]
            let key = plainKey (0x44 :: Int)
            vault <- sealedTo (alice :| []) key
            openedBy alice vault >>= (`sameKey` key)

    it
        "holds the v1 plaintext, as a plugin-wrapped payload (control: raw seal)"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            alice :| _ <- pairs ["alice"]
            recipient <-
                maybe (fail "recipient") pure $
                    parsePluginRecipient (keypairRecipient alice)
            let key = plainKey (0x45 :: Int)
            raw <-
                sealToPlugins refusingPluginUi (recipient :| []) (encodeV1Payload key)
                    >>= either (fail . show) pure
            openedBy alice raw >>= (`sameKey` key)

    it "seals the same key to different bytes each time" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            let key = plainKey (0x46 :: Int)
            first <- sealedTo (alice :| []) key
            second <- sealedTo (alice :| []) key
            first `shouldNotBe` second

    it "refuses, and returns no vault, when the plugin fails" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            sealed <-
                steered [("CWT_FAKE_FIDO2_ERROR", "no authenticator")] $
                    sealFido2Vault
                        refusingPluginUi
                        (recipientsOf (alice :| []))
                        (plainKey (0x47 :: Int))
            case sealed of
                Left (Fido2PluginFailed message) ->
                    message `shouldSatisfy` ("no authenticator" `T.isInfixOf`)
                other -> expectationFailure ("expected a plugin failure: " <> show other)

    it "names the missing plugin binary when sealing" $ do
        alice :| _ <- withFakePlugins ["fido2-hmac"] (pairs ["alice"])
        withPathOnly ["/nonexistent"] $
            sealFido2Vault
                refusingPluginUi
                (recipientsOf (alice :| []))
                (plainKey (0x48 :: Int))
                `shouldReturn` Left (Fido2PluginMissing "age-plugin-fido2-hmac")

openRefusals :: Spec
openRefusals = describe "open refusals" $ do
    it
        "answers the single opening refusal for an identity that matches no stanza"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            alice :| [bob] <- pairs ["alice", "bob"]
            vault <- sealedTo (alice :| []) (plainKey (0x51 :: Int))
            openedBy bob vault >>= (`shouldSatisfy` isNotOpened)

    it "answers it for a scrypt vault" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            scrypt <-
                sealVault
                    (factor 10)
                    (passphrase "a passphrase")
                    (plainKey (0x52 :: Int))
                    >>= either (fail . show) pure
            openedBy alice scrypt >>= (`shouldSatisfy` isNotOpened)
            -- control: the same identity opens a vault of its own kind
            own <- sealedTo (alice :| []) (plainKey (0x52 :: Int))
            openedBy alice own >>= (`sameKey` plainKey (0x52 :: Int))

    it "answers it for a file that is not a vault, empty included" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            forM_
                ["", "age-encryption.org/v1\n", "plain text", BS.replicate 400 0]
                $ \bytes -> do
                    refused <- openedBy alice bytes
                    refused `shouldSatisfy` isNotOpened
            -- control: a vault of its own kind opens
            own <- sealedTo (alice :| []) (plainKey (0x53 :: Int))
            openedBy alice own >>= (`sameKey` plainKey (0x53 :: Int))

    it "answers it for a plaintext that is not a signing key" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            recipient <-
                maybe (fail "recipient") pure $
                    parsePluginRecipient (keypairRecipient alice)
            vault <-
                sealToPlugins refusingPluginUi (recipient :| []) "just some words"
                    >>= either (fail . show) pure
            openedBy alice vault >>= (`shouldSatisfy` isNotOpened)

    it "answers it for a vault changed at any byte" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            vault <- sealedTo (alice :| []) (plainKey (0x53 :: Int))
            forM_ [0, 11 .. BS.length vault - 1] $ \position -> do
                let changed = changedAt position vault
                openedBy alice changed >>= (`shouldSatisfy` isNotOpened)
            openedBy alice vault >>= (`sameKey` plainKey (0x53 :: Int))

    it "answers it when the plugin reports an error" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            vault <- sealedTo (alice :| []) (plainKey (0x54 :: Int))
            steered [("CWT_FAKE_FIDO2_ERROR", "the key is on fire")] $
                openedBy alice vault >>= (`shouldSatisfy` isNotOpened)

    it
        "names the binary, and only then, when the plugin is not on the PATH"
        $ do
            alice :| _ <- withFakePlugins ["fido2-hmac"] (pairs ["alice"])
            vault <-
                withFakePlugins ["fido2-hmac"] $
                    sealedTo (alice :| []) (plainKey (0x55 :: Int))
            withPathOnly ["/nonexistent"] $
                openedBy alice vault
                    >>= (`shouldSatisfy` isPluginMissing "age-plugin-fido2-hmac")

    it "renders each refusal as one line that carries no secret" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            let refusals =
                    [ NotAFido2Recipient "age1whatever"
                    , NotAFido2Identity
                    , NoFido2Recipients
                    , Fido2PluginMissing "age-plugin-fido2-hmac"
                    , Fido2PluginFailed "the key is on fire"
                    , Fido2VaultRefused VaultNotOpened
                    , Fido2VaultRefused (VaultPathExists "vault.age")
                    , Fido2VaultRefused (VaultNotWritten "vault.age")
                    ]
            forM_ refusals $ \refusal -> do
                let line = renderFido2Refusal refusal
                line `shouldSatisfy` (not . T.null)
                line `shouldSatisfy` (not . T.any (== '\n'))
                line `shouldSatisfy` (not . (keypairIdentity alice `T.isInfixOf`))
            renderFido2Refusal (Fido2VaultRefused VaultNotOpened)
                `shouldBe` renderVaultRefusal VaultNotOpened
            renderFido2Refusal (Fido2PluginMissing "age-plugin-fido2-hmac")
                `shouldSatisfy` ("age-plugin-fido2-hmac" `T.isInfixOf`)

twoRecipients :: Spec
twoRecipients = describe "two recipients" $ do
    it "opens with the first identity alone" $
        withFakePlugins ["fido2-hmac"] $ do
            keys@(alice :| _) <- pairs ["alice", "bob"]
            let key = plainKey (0x61 :: Int)
            vault <- sealedTo keys key
            openedBy alice vault >>= (`sameKey` key)

    it "opens with the second identity alone" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            let key = plainKey (0x62 :: Int)
            vault <- sealedTo keys key
            openedBy (NE.last keys) vault >>= (`sameKey` key)

    it "opens with each identity alone, for any number of recipients" $
        withMaxSuccess 8 . property . forAll (choose (2, 5)) $ \n ->
            ioProperty . withFakePlugins ["fido2-hmac"] $ do
                keys <-
                    pairs (take n ["alice", "bob", "carol", "dave", "erin"])
                let key = plainKey (0x63 :: Int)
                vault <- sealedTo keys key
                outcomes <-
                    forM (NE.toList keys) $ \pair ->
                        either (const False) (const True)
                            <$> (openedBy pair vault >>= \o -> sameKey o key >> pure o)
                pure (and outcomes && length outcomes == n)

    it "does not open with the identity of a third key" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            carol :| _ <- pairs ["carol"]
            vault <- sealedTo keys (plainKey (0x64 :: Int))
            openedBy carol vault >>= (`shouldSatisfy` isNotOpened)

    it "opens with an identity file holding all, or only one of them" $
        withFakePlugins ["fido2-hmac"] $ do
            keys@(alice :| [bob]) <- pairs ["alice", "bob"]
            carol :| _ <- pairs ["carol"]
            let key = plainKey (0x65 :: Int)
            vault <- sealedTo keys key
            forM_
                [ keys
                , carol :| [bob]
                , bob :| [carol, alice]
                ]
                $ \held ->
                    openFido2Vault refusingPluginUi (identitiesOf held) vault
                        >>= (`sameKey` key)

    it "writes one stanza for each of the two recipients" $
        withFakePlugins ["fido2-hmac"] $ do
            keys <- pairs ["alice", "bob"]
            vault <- sealedTo keys (plainKey (0x66 :: Int))
            stanzaCountOf vault `shouldBe` Right 2

rekey :: Spec
rekey = describe "rekey" $ do
    it
        "moves the same key to a new set: the new opens it, the removed do not"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            old@(alice :| [bob]) <- pairs ["alice", "bob"]
            new@(carol :| [dave]) <- pairs ["carol", "dave"]
            let key = plainKey (0x71 :: Int)
            vault <- sealedTo old key
            rekeyed <-
                rekeyFido2Vault
                    refusingPluginUi
                    (identitiesOf (alice :| []))
                    (recipientsOf new)
                    vault
                    >>= either (fail . show) pure
            forM_ [carol, dave] $ \pair ->
                openedBy pair rekeyed >>= (`sameKey` key)
            forM_ [alice, bob] $ \pair ->
                openedBy pair rekeyed >>= (`shouldSatisfy` isNotOpened)
            rekeyed `shouldNotBe` vault
            stanzaCountOf rekeyed `shouldBe` Right 2

    it "keeps the signing key when the set only grows or only shrinks" $
        withFakePlugins ["fido2-hmac"] $ do
            old@(alice :| [bob]) <- pairs ["alice", "bob"]
            carol :| _ <- pairs ["carol"]
            let key = plainKey (0x72 :: Int)
            vault <- sealedTo old key
            forM_ [alice :| [bob, carol], bob :| []] $ \new -> do
                rekeyed <-
                    rekeyFido2Vault
                        refusingPluginUi
                        (identitiesOf (bob :| []))
                        (recipientsOf new)
                        vault
                        >>= either (fail . show) pure
                forM_ (NE.toList new) $ \pair ->
                    openedBy pair rekeyed >>= (`sameKey` key)

    it "leaves the vault it was given as it was, and writes nothing" $
        withFakePlugins ["fido2-hmac"] $ do
            old@(alice :| _) <- pairs ["alice", "bob"]
            new <- pairs ["carol"]
            vault <- sealedTo old (plainKey (0x73 :: Int))
            let kept = vault
            _ <-
                rekeyFido2Vault
                    refusingPluginUi
                    (identitiesOf (alice :| []))
                    (recipientsOf new)
                    vault
            vault `shouldBe` kept

    it "refuses when the identity is not one of the vault's" $
        withFakePlugins ["fido2-hmac"] $ do
            old <- pairs ["alice", "bob"]
            carol :| _ <- pairs ["carol"]
            vault <- sealedTo old (plainKey (0x74 :: Int))
            rekeyFido2Vault
                refusingPluginUi
                (identitiesOf (carol :| []))
                (recipientsOf (carol :| []))
                vault
                >>= (`shouldSatisfy` isNotOpened)

    it "refuses when the plugin fails wrapping to the new set" $
        withFakePlugins ["fido2-hmac"] $ do
            old@(alice :| _) <- pairs ["alice"]
            new <- pairs ["carol"]
            vault <- sealedTo old (plainKey (0x75 :: Int))
            -- the plugin opens the old vault and fails only wrapping to the new set
            result <-
                steered
                    [ ("CWT_FAKE_FIDO2_ERROR", "no authenticator")
                    , ("CWT_FAKE_FIDO2_ONLY_IN", "recipient-v1")
                    ]
                    $ rekeyFido2Vault
                        refusingPluginUi
                        (identitiesOf (alice :| []))
                        (recipientsOf new)
                        vault
            case result of
                Left (Fido2PluginFailed message) ->
                    message `shouldSatisfy` ("no authenticator" `T.isInfixOf`)
                other -> expectationFailure ("expected a plugin failure: " <> show other)

    it
        "refuses with the opening refusal when the plugin fails unwrapping, and not otherwise"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            old@(alice :| _) <- pairs ["alice"]
            new <- pairs ["carol"]
            vault <- sealedTo old (plainKey (0x76 :: Int))
            let rekeyed =
                    rekeyFido2Vault
                        refusingPluginUi
                        (identitiesOf (alice :| []))
                        (recipientsOf new)
                        vault
            -- control: unsteered, the same call succeeds
            rekeyed >>= (`shouldSatisfy` isRight)
            result <-
                steered
                    [ ("CWT_FAKE_FIDO2_ERROR", "no authenticator")
                    , ("CWT_FAKE_FIDO2_ONLY_IN", "identity-v1")
                    ]
                    rekeyed
            result `shouldSatisfy` isNotOpened

    it "seals a vault holding no signing key to nobody (control)" $
        withFakePlugins ["fido2-hmac"] $ do
            alice :| _ <- pairs ["alice"]
            recipient <-
                maybe (fail "recipient") pure $
                    parsePluginRecipient (keypairRecipient alice)
            junk <-
                sealToPlugins refusingPluginUi (recipient :| []) "not a key"
                    >>= either (fail . show) pure
            new <- pairs ["carol"]
            rekeyFido2Vault
                refusingPluginUi
                (identitiesOf (alice :| []))
                (recipientsOf new)
                junk
                >>= (`shouldSatisfy` isNotOpened)
