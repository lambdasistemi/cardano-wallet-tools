{- |
Module      : Cardano.Wallet.Tools.Vault.PluginSpec
Description : The client side of the age plugin protocol, against the fake plugin
License     : Apache-2.0

The client runs a real child process that speaks the protocol on its
stdin and stdout; nothing here replaces that process with an in-process
double. The fake plugin is steered through its environment to make the
client face a message, a request for a secret, a command it has no name
for and an error, and what the client answered is read from what the
plugin then did, never from the client itself.
-}
module Cardano.Wallet.Tools.Vault.PluginSpec (spec) where

import Cardano.Wallet.Tools.Vault.Plugin
import Codec.Binary.Bech32 qualified as Bech32
import Control.Monad (forM_)
import Crypto.Age.Conduit (encryptPayloadChunk)
import Crypto.Age.Header (headerParser)
import Crypto.Age.Key
    ( FileKey
    , bytesToFileKey
    , bytesToPayloadKeyNonce
    , mkPayloadKey
    )
import Crypto.Age.Payload.Ciphertext (ciphertextPayloadChunkToBytes)
import Crypto.Age.Payload.Counter
    ( incrementPayloadChunkCounter
    , zeroPayloadChunkCounter
    )
import Crypto.Age.Payload.Plaintext
    ( PlaintextPayloadChunk (..)
    , mkFinalPlaintextPayloadChunk
    , mkNormalPlaintextPayloadChunk
    )
import Data.Attoparsec.ByteString (IResult (..), parse)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text qualified as T
import Support.FakePlugin
import Support.Fido2
import Support.Vault (encryptAtFactor, withEnv, withTempDir)
import System.Directory (withCurrentDirectory)
import System.FilePath ((</>))
import System.Posix.Files (createSymbolicLink)
import Test.Hspec

spec :: Spec
spec = describe "fido2" $ describe "protocol" $ do
    recipientsAndIdentities
    stateMachines
    pluginNames
    interaction
    plugin
    framing

pluginName :: String
pluginName = "fido2-hmac"

-- | A plaintext the specs seal and open; any bytes would do.
plaintext :: ByteString
plaintext = "any bytes the vault payload could be"

-- | A key pair and the plugin recipient and identity read from it.
pairFor
    :: String -> String -> IO (Keypair, PluginRecipient, PluginIdentity)
pairFor name label = do
    pair <- fakeKeypair name label
    r <- orFail "recipient" (parsePluginRecipient (keypairRecipient pair))
    i <- orFail "identity" (parsePluginIdentity (keypairIdentity pair))
    pure (pair, r, i)
  where
    orFail what = maybe (fail ("the fake made no " <> what)) pure

recipientsAndIdentities :: Spec
recipientsAndIdentities = describe "recipients and identities" $ do
    it "takes the plugin name from the recipient, as age does" $ do
        (pair, recipient, _) <- pairFor "fido2-hmac" "alice"
        pluginRecipientName recipient `shouldBe` "fido2-hmac"
        pluginRecipientText recipient `shouldBe` keypairRecipient pair
        (_, other, _) <- pairFor "fake-other" "alice"
        pluginRecipientName other `shouldBe` "fake-other"

    it "takes the plugin name from the identity, as age does" $ do
        (pair, _, identity) <- pairFor "fido2-hmac" "alice"
        pluginIdentityName identity `shouldBe` "fido2-hmac"
        pluginIdentityText identity `shouldBe` keypairIdentity pair
        (_, _, other) <- pairFor "fake-other" "alice"
        pluginIdentityName other `shouldBe` "fake-other"

    it "names the binary age-plugin-NAME" $
        pluginBinaryName "fido2-hmac" `shouldBe` "age-plugin-fido2-hmac"

    it "refuses what is not a plugin recipient" $ do
        (pair, _, _) <- pairFor pluginName "alice"
        let r = keypairRecipient pair
            flipped = T.init r <> (if T.last r == 'q' then "p" else "q")
        forM_
            [ ""
            , "not a recipient"
            , "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
            , keypairIdentity pair
            , flipped
            , T.toUpper r <> "x"
            ]
            $ \text -> parsePluginRecipient text `shouldBe` Nothing

    it "refuses what is not a plugin identity" $ do
        (pair, _, _) <- pairFor pluginName "alice"
        let i = keypairIdentity pair
            flipped = T.init i <> (if T.last i == 'Q' then "P" else "Q")
        forM_
            [ ""
            , "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
            , keypairRecipient pair
            , flipped
            ]
            $ \text -> parsePluginIdentity text `shouldBe` Nothing

    it "refuses a plugin name that could name another path" $ do
        (_, plain, _) <- pairFor "fido2-hmac" "alice"
        parsePluginRecipient (pluginRecipientText plain) `shouldBe` Just plain
        forM_ ["../evil", "a/b", "", "a;b", "a\\b", "a:b"] $ \name -> do
            let hrp =
                    either (error . show) id $
                        Bech32.humanReadablePartFromText ("age1" <> name)
                text =
                    Bech32.encodeLenient hrp (Bech32.dataPartFromBytes "x")
            parsePluginRecipient text `shouldBe` Nothing

    it "reads keys of any length: a real plugin's carry a credential" $
        forM_ [32, 200, 400] $ \size -> do
            let encoded prefix =
                    Bech32.encodeLenient
                        (either (error . show) id (Bech32.humanReadablePartFromText prefix))
                        (Bech32.dataPartFromBytes (BS.replicate size 3))
                recipient = encoded "age1fido2-hmac"
                identity = T.toUpper (encoded "age-plugin-fido2-hmac-")
            fmap pluginRecipientName (parsePluginRecipient recipient)
                `shouldBe` Just "fido2-hmac"
            fmap pluginIdentityName (parsePluginIdentity identity)
                `shouldBe` Just "fido2-hmac"
            T.length recipient `shouldSatisfy` (> size)

    it "shows a recipient and hides an identity" $ do
        (pair, recipient, identity) <- pairFor pluginName "alice"
        show recipient
            `shouldSatisfy` (T.unpack (keypairRecipient pair) `isInfixOfS`)
        show identity
            `shouldNotSatisfy` (T.unpack (keypairIdentity pair) `isInfixOfS`)
  where
    isInfixOfS needle haystack = T.pack needle `T.isInfixOf` T.pack haystack

stateMachines :: Spec
stateMachines = describe "state machines" $ do
    it "wraps with recipient-v1: every recipient, one file key, done" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (_, b, _) <- pairFor pluginName "bob"
            (sealed, logged) <-
                loggedPlugin $
                    sealToPlugins refusingPluginUi (a :| [b]) plaintext
            _ <- either (fail . show) pure sealed
            logged
                `shouldContain` ["invoked age-plugin-fido2-hmac recipient-v1"]
            [ line
                | line <- logged
                , "received add-recipient " `isPrefixOfS` line
                ]
                `shouldBe` [ "received add-recipient " <> T.unpack (pluginRecipientText a)
                           , "received add-recipient " <> T.unpack (pluginRecipientText b)
                           ]
            let keys = [l | l <- logged, "wrap-file-key " `isPrefixOfS` l]
            map (length . drop (length ("wrap-file-key " :: String))) keys
                `shouldBe` [32]

    it "unwraps with identity-v1: the identity, then every stanza" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            (_, b, _) <- pairFor pluginName "bob"
            vault <-
                sealToPlugins refusingPluginUi (a :| [b]) plaintext
                    >>= either (fail . show) pure
            (opened, logged) <-
                loggedPlugin $
                    openWithPlugins refusingPluginUi (ai :| []) vault
            opened `shouldBe` Right plaintext
            logged
                `shouldContain` ["invoked age-plugin-fido2-hmac identity-v1"]
            length
                [ l
                | l <- logged
                , "received recipient-stanza 0 fido2-hmac " `isPrefixOfS` l
                ]
                `shouldBe` 2
            length [l | l <- logged, "received add-identity " `isPrefixOfS` l]
                `shouldBe` 1

    it "gives the plugin the identity text it was given" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            vault <-
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
            (_, logged) <-
                loggedPlugin $
                    openWithPlugins refusingPluginUi (ai :| []) vault
            logged
                `shouldContain` [ "received add-identity "
                                    <> T.unpack (pluginIdentityText ai)
                                ]
  where
    isPrefixOfS prefix s = take (length prefix) s == prefix

pluginNames :: Spec
pluginNames = describe "plugin binaries" $ do
    it "starts the plugin the recipient names, one process per plugin" $
        withFakePlugins [pluginName, "fake-other"] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (_, b, bi) <- pairFor "fake-other" "bob"
            (sealed, logged) <-
                loggedPlugin $
                    sealToPlugins refusingPluginUi (a :| [b]) plaintext
            vault <- either (fail . show) pure sealed
            logged
                `shouldContain` ["invoked age-plugin-fido2-hmac recipient-v1"]
            logged
                `shouldContain` ["invoked age-plugin-fake-other recipient-v1"]
            stanzaTagsOf vault
                `shouldBe` Right ["fido2-hmac", "fake-other"]
            openWithPlugins refusingPluginUi (bi :| []) vault
                `shouldReturn` Right plaintext

    it "names the binary when no plugin of that name is on the PATH" $
        withFakePlugins [pluginName] $ do
            (_, other, _) <- pairFor "fake-other" "bob"
            sealToPlugins refusingPluginUi (other :| []) plaintext
                `shouldReturn` Left (PluginBinaryNotFound "age-plugin-fake-other")

    it "finds no plugin on a PATH without one, to seal or to open" $ do
        (_, a, ai) <- pairFor pluginName "alice"
        vault <-
            withFakePlugins [pluginName] $
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
        withPathOnly ["/nonexistent"] $ do
            sealToPlugins refusingPluginUi (a :| []) plaintext
                `shouldReturn` Left (PluginBinaryNotFound "age-plugin-fido2-hmac")
            openWithPlugins refusingPluginUi (ai :| []) vault
                `shouldReturn` Left (PluginBinaryNotFound "age-plugin-fido2-hmac")

    it "never searches the working directory or a relative PATH entry" $ do
        (_, a, _) <- pairFor pluginName "alice"
        exe <- fakePluginExecutable
        withTempDir "relative-path" $ \dir -> do
            createSymbolicLink exe (dir </> "age-plugin-fido2-hmac")
            withCurrentDirectory dir $
                forM_ [".", "", ":", "./", "."] $ \entry ->
                    withPathOnly [entry] $
                        sealToPlugins refusingPluginUi (a :| []) plaintext
                            `shouldReturn` Left
                                (PluginBinaryNotFound "age-plugin-fido2-hmac")
            -- control: the same directory, named absolutely, finds it
            withPathOnly [dir] $
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= (`shouldSatisfy` isRight')
  where
    isRight' = either (const False) (const True)

interaction :: Spec
interaction = describe "plugin interaction" $ do
    it "shows the plugin's message through the interface and answers ok" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (ui, events) <- recordingUi noAnswers
            sealed <-
                steered [("CWT_FAKE_FIDO2_MESSAGE", "touch your key")] $
                    sealToPlugins ui (a :| []) plaintext
            sealed `shouldSatisfy` either (const False) (const True)
            events `shouldReturn` [Message "touch your key"]

    it "gives the plugin the secret the interface returned, intact" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            let secret = BC.pack (replicate 150 'p' <> "in")
            (ui, events) <-
                recordingUi noAnswers{answerSecret = Just secret}
            sealed <-
                steered
                    [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN for your key")
                    , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", BC.unpack secret)
                    ]
                    $ sealToPlugins ui (a :| []) plaintext
            sealed `shouldSatisfy` either (const False) (const True)
            events `shouldReturn` [AskedSecret "PIN for your key"]

    it
        "does not give the plugin a secret other than the one returned (control)"
        $ withFakePlugins [pluginName]
        $ do
            (_, a, _) <- pairFor pluginName "alice"
            (ui, _) <- recordingUi noAnswers{answerSecret = Just "the wrong pin"}
            sealed <-
                steered
                    [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN")
                    , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", "the right pin")
                    ]
                    $ sealToPlugins ui (a :| []) plaintext
            sealed `shouldSatisfy` isPluginFailure

    it
        "answers fail when the interface refuses a secret, and the plugin decides"
        $ withFakePlugins [pluginName]
        $ do
            (_, a, _) <- pairFor pluginName "alice"
            (ui, events) <- recordingUi noAnswers
            sealed <-
                steered [("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN")] $
                    sealToPlugins ui (a :| []) plaintext
            sealed `shouldSatisfy` isPluginFailure
            events `shouldReturn` [AskedSecret "PIN"]

    it "relays a request for a public value, and the answer" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (ui, events) <-
                recordingUi noAnswers{answerPublic = Just "credential 7"}
            sealed <-
                steered
                    [ ("CWT_FAKE_FIDO2_PUBLIC_PROMPT", "Which credential?")
                    , ("CWT_FAKE_FIDO2_PUBLIC_EXPECTED", "credential 7")
                    ]
                    $ sealToPlugins ui (a :| []) plaintext
            sealed `shouldSatisfy` either (const False) (const True)
            events `shouldReturn` [AskedPublic "Which credential?"]

    it "relays a confirmation: the strings it offers, and the choice made" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (yesUi, yesEvents) <-
                recordingUi noAnswers{answerConfirm = Just True}
            (noUi, _) <- recordingUi noAnswers{answerConfirm = Just False}
            let steer = [("CWT_FAKE_FIDO2_CONFIRM_PROMPT", "Insert the key")]
            steered steer (sealToPlugins yesUi (a :| []) plaintext)
                >>= (`shouldSatisfy` either (const False) (const True))
            yesEvents
                `shouldReturn` [AskedConfirm "Insert the key" "yes" (Just "no")]
            steered steer (sealToPlugins noUi (a :| []) plaintext)
                >>= (`shouldSatisfy` isPluginFailure)

    it "answers unsupported to a command the protocol does not define" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            -- the plugin fails unless the client answers `unsupported`
            sealed <-
                steered [("CWT_FAKE_FIDO2_UNKNOWN_COMMAND", "frobnicate")] $
                    sealToPlugins refusingPluginUi (a :| []) plaintext
            vault <- either (fail . show) pure sealed
            opened <-
                steered [("CWT_FAKE_FIDO2_UNKNOWN_COMMAND", "frobnicate")] $
                    openWithPlugins refusingPluginUi (ai :| []) vault
            opened `shouldBe` Right plaintext

    it "never prints or returns the secret, the file key or the identity" $
        withFakePlugins [pluginName] $ do
            (pair, a, ai) <- pairFor pluginName "alice"
            let secret = "needle-pin-9f3a1c"
            (ui, _) <- recordingUi noAnswers{answerSecret = Just secret}
            ((sealed, opened), logged) <-
                loggedPlugin
                    $ steered
                        [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN")
                        , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", BC.unpack secret)
                        ]
                    $ do
                        s <- sealToPlugins ui (a :| []) plaintext
                        vault <- either (fail . show) pure s
                        o <- openWithPlugins ui (ai :| []) vault
                        pure (vault, o)
            let fileKeys =
                    [ drop (length ("wrap-file-key " :: String)) l
                    | l <- logged
                    , take 14 l == "wrap-file-key "
                    ]
            length fileKeys `shouldBe` 1
            opened `shouldBe` Right plaintext
            sealed `shouldSatisfy` (not . BS.isInfixOf secret)
            forM_ fileKeys $ \hexKey ->
                sealed `shouldSatisfy` (not . BS.isInfixOf (BC.pack hexKey))
            let rendered =
                    T.unpack . renderPluginRefusal
                        <$> [ PluginBinaryNotFound "age-plugin-x"
                            , PluginFailed "plugin said no"
                            , PluginProtocolViolation "bad stanza"
                            , PluginNoStanzaUnwrapped
                            , PluginFileRefused
                            ]
            forM_ rendered $ \line -> do
                line `shouldSatisfy` (not . null)
                line `shouldSatisfy` notElem '\n'
                line
                    `shouldSatisfy` (not . (T.unpack (keypairIdentity pair) `isInfixOfS`))
  where
    isInfixOfS needle haystack = T.pack needle `T.isInfixOf` T.pack haystack

plugin :: Spec
plugin = describe "plugin failures" $ do
    it
        "refuses, naming the plugin's message, when the plugin reports an error"
        $ withFakePlugins [pluginName]
        $ do
            (_, a, ai) <- pairFor pluginName "alice"
            sealed <-
                steered [("CWT_FAKE_FIDO2_ERROR", "the key is on fire")] $
                    sealToPlugins refusingPluginUi (a :| []) plaintext
            case sealed of
                Left (PluginFailed message) ->
                    message `shouldSatisfy` ("the key is on fire" `T.isInfixOf`)
                other -> expectationFailure ("expected a plugin error: " <> show other)
            vault <-
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
            opened <-
                steered [("CWT_FAKE_FIDO2_ERROR", "the key is on fire")] $
                    openWithPlugins refusingPluginUi (ai :| []) vault
            opened `shouldSatisfy` either (const True) (const False)

    it "refuses when the plugin dies before speaking, and does not hang" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            sealed <-
                within . steered [("CWT_FAKE_FIDO2_EXIT_EARLY", "1")] $
                    sealToPlugins refusingPluginUi (a :| []) plaintext
            sealed `shouldSatisfy` either (const True) (const False)

    it "refuses output that is no stanza, as a protocol violation" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            sealed <-
                within . steered [("CWT_FAKE_FIDO2_GARBAGE", "1")] $
                    sealToPlugins refusingPluginUi (a :| []) plaintext
            sealed `shouldSatisfy` isProtocolViolation

    it "finds no file key when no identity matches a stanza" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (_, _, bi) <- pairFor pluginName "bob"
            vault <-
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
            openWithPlugins refusingPluginUi (bi :| []) vault
                `shouldReturn` Left PluginNoStanzaUnwrapped

    it "finds no file key in a vault of another kind of stanza" $
        withFakePlugins [pluginName] $ do
            (_, _, ai) <- pairFor pluginName "alice"
            scrypt <- encryptAtFactor 10 "a passphrase" plaintext
            openWithPlugins refusingPluginUi (ai :| []) scrypt
                `shouldReturn` Left PluginNoStanzaUnwrapped
  where
    isProtocolViolation = \case
        Left (PluginProtocolViolation _) -> True
        _ -> False

isPluginFailure :: Either PluginRefusal a -> Bool
isPluginFailure = either (const True) (const False)

framing :: Spec
framing = describe "age file framing" $ do
    it "writes a binary age v1 file with one stanza per recipient" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            (_, b, _) <- pairFor pluginName "bob"
            (_, c, _) <- pairFor pluginName "carol"
            vault <-
                sealToPlugins refusingPluginUi (a :| [b, c]) plaintext
                    >>= either (fail . show) pure
            vault `shouldSatisfy` BS.isPrefixOf "age-encryption.org/v1\n"
            vault
                `shouldNotSatisfy` BS.isInfixOf "-----BEGIN AGE ENCRYPTED FILE-----"
            stanzaTagsOf vault `shouldBe` Right (replicate 3 "fido2-hmac")

    it "opens what it sealed, at every payload size around a chunk" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            forM_ [0, 1, 65535, 65536, 65537, 131072, 200000] $ \size -> do
                let body = BS.pack (take size (cycle [0 .. 250]))
                vault <-
                    sealToPlugins refusingPluginUi (a :| []) body
                        >>= either (fail . show) pure
                openWithPlugins refusingPluginUi (ai :| []) vault
                    `shouldReturn` Right body

    it "refuses a payload whose final chunk is empty after other chunks" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            (vault, logged) <-
                loggedPlugin $
                    sealToPlugins refusingPluginUi (a :| []) plaintext
                        >>= either (fail . show) pure
            let full = BS.replicate 65536 1
            -- control: a final chunk that is not empty makes a payload that opens
            fine <- withForgedPayload vault logged [(False, full), (True, "tail")]
            openWithPlugins refusingPluginUi (ai :| []) fine
                `shouldReturn` Right (full <> "tail")
            forged <-
                withForgedPayload vault logged [(False, full), (True, BS.empty)]
            openWithPlugins refusingPluginUi (ai :| []) forged
                >>= (`shouldSatisfy` isPluginFailure)
            -- the empty payload is one empty final chunk, and opens
            alone <- withForgedPayload vault logged [(True, BS.empty)]
            openWithPlugins refusingPluginUi (ai :| []) alone
                `shouldReturn` Right BS.empty

    it "seals the same plaintext to different bytes each time" $
        withFakePlugins [pluginName] $ do
            (_, a, _) <- pairFor pluginName "alice"
            [first, second] <-
                mapM
                    (const (sealToPlugins refusingPluginUi (a :| []) plaintext))
                    [1 :: Int, 2]
                    >>= mapM (either (fail . show) pure)
            first `shouldNotBe` second

    it "refuses a file that is not an age file" $
        withFakePlugins [pluginName] $ do
            (_, _, ai) <- pairFor pluginName "alice"
            forM_ ["", "not an age file", "age-encryption.org/v1\n"] $ \bytes -> do
                refused <- openWithPlugins refusingPluginUi (ai :| []) bytes
                refused `shouldSatisfy` isPluginFailure

    it "refuses a file whose header or payload was changed, at any byte" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            vault <-
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
            let positions = [0, 7 .. BS.length vault - 1]
            length positions `shouldSatisfy` (> 10)
            forM_ positions $ \position -> do
                let changed = changedAt position vault
                openWithPlugins refusingPluginUi (ai :| []) changed
                    >>= (`shouldSatisfy` isPluginFailure)
            -- control: the unchanged vault opens
            openWithPlugins refusingPluginUi (ai :| []) vault
                `shouldReturn` Right plaintext

    it "refuses a truncated file at every length" $
        withFakePlugins [pluginName] $ do
            (_, a, ai) <- pairFor pluginName "alice"
            vault <-
                sealToPlugins refusingPluginUi (a :| []) plaintext
                    >>= either (fail . show) pure
            forM_ [0, 5 .. BS.length vault - 1] $ \len -> do
                refused <-
                    openWithPlugins refusingPluginUi (ai :| []) (BS.take len vault)
                refused `shouldSatisfy` isPluginFailure

    it "is unaffected by an unrelated environment variable (control)" $
        withFakePlugins [pluginName] $
            withEnv [("CWT_UNRELATED", "1")] $ do
                (_, a, ai) <- pairFor pluginName "alice"
                vault <-
                    sealToPlugins refusingPluginUi (a :| []) plaintext
                        >>= either (fail . show) pure
                openWithPlugins refusingPluginUi (ai :| []) vault
                    `shouldReturn` Right plaintext

{- | The header of an age file and the file key a fake plugin logged for
it, joined to a payload made here, chunk by chunk, with the age library's
chunk functions: the oracle for what a payload may and may not be.
-}
withForgedPayload
    :: ByteString
    -> [String]
    -> [(Bool, ByteString)]
    -> IO ByteString
withForgedPayload vault logged chunks = do
    headerLength <- case parse headerParser vault of
        Done rest _ -> pure (BS.length vault - BS.length rest)
        _ -> fail "the sealed vault has no header"
    hexKey <- case [drop 14 l | l <- logged, take 14 l == "wrap-file-key "] of
        [one] -> pure one
        _ -> fail "the fake logged no single file key"
    fileKey <- fileKeyOf (BC.pack hexKey)
    nonce <-
        maybe (fail "nonce") pure $
            bytesToPayloadKeyNonce (BS.replicate 16 0x07)
    let key = mkPayloadKey nonce fileKey
        counters =
            take (length chunks) $
                iterate
                    (>>= incrementPayloadChunkCounter)
                    (Just zeroPayloadChunkCounter)
    sealed <- case (sequence counters, traverse plaintextChunk chunks) of
        (Just numbered, Just plaintexts) ->
            pure
                [ ciphertextPayloadChunkToBytes (encryptPayloadChunk key counter chunk)
                | (counter, chunk) <- zip numbered plaintexts
                ]
        _ -> fail "the forged chunks could not be made"
    pure
        ( BS.take headerLength vault <> BS.replicate 16 0x07 <> BS.concat sealed
        )
  where
    plaintextChunk (isFinal, bytes)
        | isFinal =
            PlaintextPayloadChunkFinal <$> mkFinalPlaintextPayloadChunk bytes
        | otherwise =
            PlaintextPayloadChunkNormal <$> mkNormalPlaintextPayloadChunk bytes

fileKeyOf :: ByteString -> IO FileKey
fileKeyOf hex = case B16.decode hex of
    Right bytes | Just key <- bytesToFileKey (BA.convert bytes) -> pure key
    _ -> fail "the logged file key is not 16 bytes of hex"
