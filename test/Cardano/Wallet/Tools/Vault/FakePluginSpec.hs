{- |
Module      : Cardano.Wallet.Tools.Vault.FakePluginSpec
Description : The fake plugin is a plugin: it speaks the protocol and can say no
License     : Apache-2.0

The vault specs trust the fake plugin as an oracle, so the fake is held
to the protocol first, by a conversation written by hand and independent
of the client in @cwt@: what it sends for a recipient, what it gives
back for an identity, that an identity unwraps only the stanzas wrapped
for its own recipient, that each steering knob makes it send the command
it names, and that it fails when the client answers wrongly. A fake that
could not fail would make every green below it empty.
-}
module Cardano.Wallet.Tools.Vault.FakePluginSpec (spec) where

import Control.Monad (forM_)
import Crypto.Age.Header (Stanza (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.FakePlugin
import System.Directory (findExecutable)
import System.Exit (ExitCode (..))
import System.Process (readProcessWithExitCode)
import Test.Hspec

spec :: Spec
spec = describe "fido2" $ describe "protocol" $ describe "fake plugin" $ do
    keys
    wrapping
    unwrapping
    steering

fileKey :: ByteString
fileKey = "0123456789abcdef"

-- | The plugin linked under a name, as the examples invoke it.
linked :: String -> IO FilePath
linked name =
    findExecutable ("age-plugin-" <> name)
        >>= maybe (fail "the fake is not linked") pure

addRecipient :: Text -> Stanza
addRecipient text =
    Stanza
        { sTag = "add-recipient"
        , sArgs = [TE.encodeUtf8 text]
        , sBody = ""
        }

addIdentity :: Text -> Stanza
addIdentity text =
    Stanza
        { sTag = "add-identity"
        , sArgs = [TE.encodeUtf8 text]
        , sBody = ""
        }

wrapFileKey :: ByteString -> Stanza
wrapFileKey key = Stanza{sTag = "wrap-file-key", sArgs = [], sBody = key}

-- | A stanza the plugin sent, re-addressed to a file index for another conversation.
stanzaFor :: Int -> Stanza -> Stanza
stanzaFor index stanza =
    stanza
        { sArgs = (TE.encodeUtf8 . T.pack . show) index : drop 1 (sArgs stanza)
        }

-- | The commands of a conversation, without their data, for comparison.
tagsOf :: Exchange -> [ByteString]
tagsOf = map sTag . exchangeSent

-- | The first command the plugin sent.
firstSent :: Exchange -> Stanza
firstSent exchange = case exchangeSent exchange of
    (s : _) -> s
    [] -> error "the plugin sent nothing"

-- | The reply to every command: ok.
allOk :: Stanza -> Stanza
allOk = const okReply

{- | The stanza a plugin wrapped a file key into, in a conversation that
sent one recipient and one file key.
-}
wrappedFor :: String -> Keypair -> IO Stanza
wrappedFor name pair = do
    exe <- linked name
    exchange <-
        converse
            exe
            "recipient-v1"
            [addRecipient (keypairRecipient pair), wrapFileKey fileKey]
            allOk
    case exchangeSent exchange of
        [stanza, _done] -> pure stanza
        other -> fail ("expected one stanza and done, got " <> show (length other))

keys :: Spec
keys = describe "keys" $ do
    it "makes the same pair for the same label and another for another" $ do
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            again <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            keypairRecipient again `shouldBe` keypairRecipient alice
            keypairIdentity again `shouldBe` keypairIdentity alice
            keypairRecipient bob `shouldNotBe` keypairRecipient alice
            keypairIdentity bob `shouldNotBe` keypairIdentity alice

    it
        "encodes a recipient and an identity the way age encodes plugin keys"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            pair <- fakeKeypair "fido2-hmac" "alice"
            keypairRecipient pair
                `shouldSatisfy` ("age1fido2-hmac1" `T.isPrefixOf`)
            keypairIdentity pair
                `shouldSatisfy` ("AGE-PLUGIN-FIDO2-HMAC-1" `T.isPrefixOf`)

    it "refuses a state machine it does not know" $
        withFakePlugins ["fido2-hmac"] $ do
            exe <- linked "fido2-hmac"
            (code, _, _) <-
                readProcessWithExitCode exe ["--age-plugin=nonsense"] ""
            code `shouldNotBe` ExitSuccess

wrapping :: Spec
wrapping = describe "recipient-v1" $ do
    it "sends one stanza per recipient and file key, then done" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "recipient-v1"
                    [addRecipient (keypairRecipient alice), wrapFileKey fileKey]
                    allOk
            tagsOf exchange `shouldBe` ["recipient-stanza", "done"]
            exchangeExit exchange `shouldBe` ExitSuccess
            let stanza = firstSent exchange
            sArgs stanza `shouldSatisfy` ((== 3) . length)
            take 2 (sArgs stanza) `shouldBe` ["0", "fido2-hmac"]
            BS.length (sBody stanza) `shouldBe` 44
            sBody stanza `shouldSatisfy` (not . BS.isInfixOf fileKey)

    it "wraps every file key to every recipient, with the file indices" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "recipient-v1"
                    [ addRecipient (keypairRecipient alice)
                    , wrapFileKey fileKey
                    , addRecipient (keypairRecipient bob)
                    , wrapFileKey "another file key"
                    ]
                    allOk
            tagsOf exchange
                `shouldBe` replicate 4 "recipient-stanza" <> ["done"]
            map (take 1 . sArgs) (init (exchangeSent exchange))
                `shouldBe` [["0"], ["0"], ["1"], ["1"]]

    it "ignores a command of the first phase it does not know" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "recipient-v1"
                    [ Stanza{sTag = "grease-q7", sArgs = ["x"], sBody = "junk"}
                    , addRecipient (keypairRecipient alice)
                    , wrapFileKey fileKey
                    , Stanza{sTag = "extension-labels", sArgs = [], sBody = ""}
                    ]
                    allOk
            tagsOf exchange `shouldBe` ["recipient-stanza", "done"]
            exchangeExit exchange `shouldBe` ExitSuccess

    it "refuses, naming the recipient, one that is not its own" $
        withFakePlugins ["fido2-hmac", "fake-other"] $ do
            other <- fakeKeypair "fake-other" "alice"
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "recipient-v1"
                    [addRecipient (keypairRecipient other), wrapFileKey fileKey]
                    allOk
            tagsOf exchange `shouldBe` ["error", "done"]
            take 2 (sArgs (firstSent exchange))
                `shouldBe` ["recipient", "0"]
            exchangeExit exchange `shouldNotBe` ExitSuccess

unwrapping :: Spec
unwrapping = describe "identity-v1" $ do
    it "gives the file key back to the identity of the recipient" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            stanza <- wrappedFor "fido2-hmac" alice
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "identity-v1"
                    [addIdentity (keypairIdentity alice), stanzaFor 0 stanza]
                    allOk
            tagsOf exchange `shouldBe` ["file-key", "done"]
            let given = firstSent exchange
            sArgs given `shouldBe` ["0"]
            sBody given `shouldBe` fileKey

    it "gives nothing to the identity of another recipient" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            stanza <- wrappedFor "fido2-hmac" alice
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "identity-v1"
                    [addIdentity (keypairIdentity bob), stanzaFor 0 stanza]
                    allOk
            tagsOf exchange `shouldBe` ["done"]
            exchangeExit exchange `shouldBe` ExitSuccess

    it "gives the file key to the one identity of several that matches" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            carol <- fakeKeypair "fido2-hmac" "carol"
            stanza <- wrappedFor "fido2-hmac" bob
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "identity-v1"
                    [ addIdentity (keypairIdentity alice)
                    , addIdentity (keypairIdentity bob)
                    , addIdentity (keypairIdentity carol)
                    , stanzaFor 0 stanza
                    ]
                    allOk
            map sBody (take 1 (exchangeSent exchange)) `shouldBe` [fileKey]

    it "ignores a stanza of a type it does not know" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            exchange <-
                converse
                    exe
                    "identity-v1"
                    [ addIdentity (keypairIdentity alice)
                    , Stanza
                        { sTag = "recipient-stanza"
                        , sArgs = ["0", "scrypt", "c2FsdA", "10"]
                        , sBody = "body"
                        }
                    ]
                    allOk
            tagsOf exchange `shouldBe` ["done"]
            exchangeExit exchange `shouldBe` ExitSuccess

    it "gives each file its own key, by file index" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            wrapped <-
                converse
                    exe
                    "recipient-v1"
                    [ addRecipient (keypairRecipient alice)
                    , wrapFileKey fileKey
                    , wrapFileKey "another file key"
                    ]
                    allOk
            (first, second) <- case exchangeSent wrapped of
                (a : b : _) -> pure (a, b)
                _ -> fail "expected two stanzas"
            exchange <-
                converse
                    exe
                    "identity-v1"
                    [ addIdentity (keypairIdentity alice)
                    , stanzaFor 0 first
                    , stanzaFor 1 second
                    ]
                    allOk
            map (\s -> (sArgs s, sBody s)) (init (exchangeSent exchange))
                `shouldBe` [(["0"], fileKey), (["1"], "another file key")]

steering :: Spec
steering = describe "steering" $ do
    forM_
        [
            ( "a message"
            , [("CWT_FAKE_FIDO2_MESSAGE", "touch the key")]
            , "msg"
            , "touch the key"
            )
        ,
            ( "a request for a secret"
            , [("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN?")]
            , "request-secret"
            , "PIN?"
            )
        ,
            ( "a request for a public value"
            , [("CWT_FAKE_FIDO2_PUBLIC_PROMPT", "Which?")]
            , "request-public"
            , "Which?"
            )
        ,
            ( "a confirmation"
            , [("CWT_FAKE_FIDO2_CONFIRM_PROMPT", "Plug it in")]
            , "confirm"
            , "Plug it in"
            )
        ,
            ( "an unknown command"
            , [("CWT_FAKE_FIDO2_UNKNOWN_COMMAND", "frobnicate")]
            , "frobnicate"
            , "some data"
            )
        ]
        $ \(what, environment, tag, body) ->
            it ("sends " <> what <> " before its stanza") $
                withFakePlugins ["fido2-hmac"] $ do
                    alice <- fakeKeypair "fido2-hmac" "alice"
                    exe <- linked "fido2-hmac"
                    exchange <-
                        steered environment $
                            converse
                                exe
                                "recipient-v1"
                                [ addRecipient (keypairRecipient alice)
                                , wrapFileKey fileKey
                                ]
                                ( \s ->
                                    if sTag s == "confirm"
                                        then okReply{sArgs = ["yes"]}
                                        else
                                            if sTag s == "frobnicate"
                                                then unsupportedReply
                                                else okReply{sBody = "reply"}
                                )
                    map sTag (take 1 (exchangeSent exchange)) `shouldBe` [tag]
                    map sBody (take 1 (exchangeSent exchange))
                        `shouldBe` [TE.encodeUtf8 (T.pack body)]

    it "accepts the expected secret and refuses another (control)" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            let environment =
                    [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN?")
                    , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", "1234")
                    ]
                phase =
                    [addRecipient (keypairRecipient alice), wrapFileKey fileKey]
            right <-
                steered environment $
                    converse exe "recipient-v1" phase (const okReply{sBody = "1234"})
            exchangeExit right `shouldBe` ExitSuccess
            tagsOf right `shouldBe` ["request-secret", "recipient-stanza", "done"]
            wrong <-
                steered environment $
                    converse exe "recipient-v1" phase (const okReply{sBody = "4321"})
            exchangeExit wrong `shouldNotBe` ExitSuccess
            tagsOf wrong `shouldBe` ["request-secret", "error", "done"]

    it "fails unless an unknown command is answered unsupported (control)" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            let environment = [("CWT_FAKE_FIDO2_UNKNOWN_COMMAND", "frobnicate")]
                phase =
                    [addRecipient (keypairRecipient alice), wrapFileKey fileKey]
            answered <-
                steered environment $
                    converse
                        exe
                        "recipient-v1"
                        phase
                        ( \s ->
                            if sTag s == "frobnicate"
                                then unsupportedReply
                                else okReply
                        )
            exchangeExit answered `shouldBe` ExitSuccess
            ignored <-
                steered environment $ converse exe "recipient-v1" phase allOk
            exchangeExit ignored `shouldNotBe` ExitSuccess
            tagsOf ignored `shouldBe` ["frobnicate", "error", "done"]

    it
        "steers one state machine only when told to, the other works normally"
        $ withFakePlugins ["fido2-hmac"]
        $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            stanza <- wrappedFor "fido2-hmac" alice
            let wrap =
                    converse
                        exe
                        "recipient-v1"
                        [addRecipient (keypairRecipient alice), wrapFileKey fileKey]
                        allOk
                unwrap =
                    converse
                        exe
                        "identity-v1"
                        [addIdentity (keypairIdentity alice), stanzaFor 0 stanza]
                        allOk
                failing machine =
                    [ ("CWT_FAKE_FIDO2_ERROR", "disk on fire")
                    , ("CWT_FAKE_FIDO2_ONLY_IN", machine)
                    ]
            wrapped <- steered (failing "identity-v1") wrap
            tagsOf wrapped `shouldBe` ["recipient-stanza", "done"]
            unwrapped <- steered (failing "recipient-v1") unwrap
            tagsOf unwrapped `shouldBe` ["file-key", "done"]
            refusedWrap <- steered (failing "recipient-v1") wrap
            tagsOf refusedWrap `shouldBe` ["error", "done"]
            refusedUnwrap <- steered (failing "identity-v1") unwrap
            tagsOf refusedUnwrap `shouldBe` ["error", "done"]

    it "sends an error instead of stanzas when told to" $
        withFakePlugins ["fido2-hmac"] $ do
            alice <- fakeKeypair "fido2-hmac" "alice"
            exe <- linked "fido2-hmac"
            exchange <-
                steered [("CWT_FAKE_FIDO2_ERROR", "disk on fire")] $
                    converse
                        exe
                        "recipient-v1"
                        [addRecipient (keypairRecipient alice), wrapFileKey fileKey]
                        allOk
            tagsOf exchange `shouldBe` ["error", "done"]
            sBody (firstSent exchange) `shouldBe` "disk on fire"
            exchangeExit exchange `shouldNotBe` ExitSuccess
