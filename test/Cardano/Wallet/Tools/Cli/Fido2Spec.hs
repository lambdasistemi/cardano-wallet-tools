{- |
Module      : Cardano.Wallet.Tools.Cli.Fido2Spec
Description : The cwt FIDO2 commands: flags, files, terminal and signing
License     : Apache-2.0

What an operator of @cwt@ can say and what comes back, against the fake
plugin. The flags are parsed by the library's own parsers; the handlers
run against real files; the terminal interface runs against a
pseudo-terminal; the @cwt@ program itself is run as a child process for
the dispatch the library cannot see. A signature from a FIDO2 vault is
compared, byte for byte, with the witness @cardano-cli@ made.
-}
module Cardano.Wallet.Tools.Cli.Fido2Spec (spec) where

import Cardano.Wallet.Tools.Cli.Fido2
import Cardano.Wallet.Tools.Cli.Vault
    ( SigningKeySource
    , signingKeySourceParser
    )
import Cardano.Wallet.Tools.Sign
    ( Signer (..)
    , attachWitnesses
    , encodeDetachedWitness
    , transactionBodyBytes
    )
import Cardano.Wallet.Tools.Vault.Plugin
    ( PluginUi (..)
    , refusingPluginUi
    )
import Control.Applicative ((<|>))
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (forM_)
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.List.NonEmpty (NonEmpty (..))
import Data.List.NonEmpty qualified as NE
import Data.Maybe (fromMaybe)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.FakePlugin
import Support.Fido2
import Support.Vault
import System.Directory (doesPathExist, listDirectory)
import System.Exit (ExitCode (..))
import System.FilePath ((</>))
import System.IO (Handle, IOMode (..), hFlush, withFile)
import System.Posix.Files
    ( createSymbolicLink
    , fileMode
    , getFileStatus
    )
import System.Posix.IO
    ( OpenFileFlags (..)
    , OpenMode (ReadWrite, WriteOnly)
    , closeFd
    , defaultFileFlags
    , dupTo
    , fdToHandle
    , openFd
    , stdError
    )
import System.Posix.Process
    ( ProcessStatus (..)
    , createSession
    , exitImmediately
    , forkProcess
    , getProcessStatus
    )
import System.Posix.Terminal
    ( getSlaveTerminalName
    , openPseudoTerminal
    )
import System.Posix.Types (Fd)
import System.Process
    ( CreateProcess (..)
    , proc
    , readCreateProcessWithExitCode
    )
import Test.Hspec

spec :: Spec
spec = do
    describe "fido2" $ describe "protocol" $ do
        parsing
        creating
        terminalInterface
        throughTheProgram
    describe "fido2" $ describe "rekey" rekeying
    describe "fido2" $ describe "golden witness" goldenWitness

-- * Fixtures

signingKeyFile :: FilePath -> IO FilePath
signingKeyFile dir = do
    let path = dir </> "payment.skey"
    BS.writeFile path (seedEnvelope (seedKey 0x91))
    pure path

seedHex :: ByteString
seedHex = B16.encode (seedKey 0x91)

createOptionsFor
    :: FilePath -> FilePath -> NonEmpty Keypair -> IO VaultCreateOptions
createOptionsFor key out keys =
    either fail pure $
        parseArgs vaultCreateParser $
            ["--fido2", "--signing-key", key, "--out", out]
                <> concat
                    [["--recipient", T.unpack (keypairRecipient k)] | k <- NE.toList keys]

rekeyOptionsFor
    :: FilePath
    -> FilePath
    -> FilePath
    -> NonEmpty Keypair
    -> IO VaultRekeyOptions
rekeyOptionsFor vault identity out keys =
    either fail pure $
        parseArgs vaultRekeyParser $
            ["--vault", vault, "--fido2-identity", identity, "--out", out]
                <> concat
                    [["--recipient", T.unpack (keypairRecipient k)] | k <- NE.toList keys]

-- | A vault of the seed key, made by the create handler, and its path.
createdVault :: FilePath -> NonEmpty Keypair -> IO FilePath
createdVault dir keys = do
    key <- signingKeyFile dir
    let out = dir </> "vault.age"
    options <- createOptionsFor key out keys
    runVaultCreate refusingPluginUi options `shouldReturn` Right ()
    pure out

identityFileFor :: FilePath -> NonEmpty Keypair -> IO FilePath
identityFileFor dir keys = do
    let path = dir </> "identity"
    BS.writeFile path (identityFileOf keys)
    pure path

parsing :: Spec
parsing = describe "flags" $ do
    it "takes the recipients, the key and the file of create" $
        parseArgs
            vaultCreateParser
            [ "--fido2"
            , "--recipient"
            , "age1fido2-hmac1aaa"
            , "--recipient"
            , "age1fido2-hmac1bbb"
            , "--signing-key"
            , "k.skey"
            , "--out"
            , "v.age"
            ]
            `shouldBe` Right
                VaultCreateOptions
                    { createRecipients = "age1fido2-hmac1aaa" :| ["age1fido2-hmac1bbb"]
                    , createSigningKey = "k.skey"
                    , createOut = "v.age"
                    }

    it "refuses create with no recipient, and takes it with one" $ do
        let rest = ["--fido2", "--signing-key", "k.skey", "--out", "v.age"]
        parseArgs vaultCreateParser (rest <> ["--recipient", "r"])
            `shouldSatisfy` isRight'
        parseArgs vaultCreateParser rest `shouldSatisfy` isLeft'

    it "refuses create without --fido2, the key or the file" $ do
        parseArgs
            vaultCreateParser
            ["--fido2", "--recipient", "r", "--signing-key", "k", "--out", "o"]
            `shouldSatisfy` isRight'
        forM_
            [ ["--recipient", "r", "--signing-key", "k", "--out", "o"]
            , ["--fido2", "--recipient", "r", "--out", "o"]
            , ["--fido2", "--recipient", "r", "--signing-key", "k"]
            ]
            $ \args -> parseArgs vaultCreateParser args `shouldSatisfy` isLeft'

    it
        "takes the vault, the identity, the recipients and the file of rekey"
        $ parseArgs
            vaultRekeyParser
            [ "--vault"
            , "old.age"
            , "--fido2-identity"
            , "id.txt"
            , "--recipient"
            , "age1fido2-hmac1ccc"
            , "--out"
            , "new.age"
            ]
            `shouldBe` Right
                VaultRekeyOptions
                    { rekeyVault = "old.age"
                    , rekeyIdentity = "id.txt"
                    , rekeyRecipients = "age1fido2-hmac1ccc" :| []
                    , rekeyOut = "new.age"
                    }

    it "refuses rekey with no recipient, no identity, no vault or no file" $ do
        parseArgs
            vaultRekeyParser
            [ "--vault"
            , "o"
            , "--fido2-identity"
            , "i"
            , "--recipient"
            , "r"
            , "--out"
            , "n"
            ]
            `shouldSatisfy` isRight'
        forM_
            [ ["--vault", "o", "--fido2-identity", "i", "--out", "n"]
            , ["--vault", "o", "--recipient", "r", "--out", "n"]
            , ["--fido2-identity", "i", "--recipient", "r", "--out", "n"]
            , ["--vault", "o", "--fido2-identity", "i", "--recipient", "r"]
            ]
            $ \args -> parseArgs vaultRekeyParser args `shouldSatisfy` isLeft'

    it "takes a FIDO2 vault and its identity as a key source for sign" $
        parseArgs
            fido2KeySourceParser
            ["--fido2-vault", "v.age", "--fido2-identity", "id.txt"]
            `shouldBe` Right
                Fido2KeySource
                    { fido2VaultPath = "v.age"
                    , fido2IdentityPath = "id.txt"
                    }

    it "refuses a FIDO2 vault without its identity" $ do
        parseArgs
            fido2KeySourceParser
            ["--fido2-vault", "v.age", "--fido2-identity", "i"]
            `shouldSatisfy` isRight'
        parseArgs fido2KeySourceParser ["--fido2-vault", "v.age"]
            `shouldSatisfy` isLeft'

    it "sits beside the other signing key sources: each is told apart" $ do
        let either' =
                (Left <$> signingKeySourceParser) <|> (Right <$> fido2KeySourceParser)
        parseArgs either' ["--signing-key", "k.skey"]
            `shouldSatisfy` isLeftSource
        parseArgs either' ["--fido2-vault", "v", "--fido2-identity", "i"]
            `shouldSatisfy` isRightSource
        parseArgs
            either'
            ["--signing-key", "k", "--fido2-vault", "v", "--fido2-identity", "i"]
            `shouldSatisfy` isLeft'
  where
    isLeft' = either (const True) (const False)
    isRight' = either (const False) (const True)
    isLeftSource
        :: Either String (Either SigningKeySource Fido2KeySource) -> Bool
    isLeftSource = \case
        Right (Left _) -> True
        _ -> False
    isRightSource
        :: Either String (Either SigningKeySource Fido2KeySource) -> Bool
    isRightSource = \case
        Right (Right _) -> True
        _ -> False

creating :: Spec
creating = describe "create" $ do
    it "writes a vault only the recipients' identities open, mode 0600" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-create" $ \dir -> do
                keys@(alice :| [bob]) <- two
                out <- createdVault dir keys
                mode <- (.&. 0o777) . fileMode <$> getFileStatus out
                mode `shouldBe` 0o600
                vault <- BS.readFile out
                openedBy alice vault >>= (`sameKey` plainKey (0x91 :: Int))
                openedBy bob vault >>= (`sameKey` plainKey (0x91 :: Int))

    it
        "refuses a recipient that is not a fido2-hmac recipient, writing nothing"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-create"
        $ \dir -> do
            key <- signingKeyFile dir
            let out = dir </> "vault.age"
            forM_
                [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
                , "not a recipient"
                ]
                $ \text -> do
                    let options =
                            VaultCreateOptions (text :| []) key out
                    result <- runVaultCreate refusingPluginUi options
                    result `shouldSatisfy` isLeftContaining "recipient"
                    doesPathExist out `shouldReturn` False

    it "refuses, and leaves untouched, an existing file" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-create" $ \dir -> do
                keys <- two
                key <- signingKeyFile dir
                let out = dir </> "vault.age"
                BS.writeFile out "an existing file"
                options <- createOptionsFor key out keys
                result <- runVaultCreate refusingPluginUi options
                result `shouldSatisfy` isLeftContaining "already exists"
                BS.readFile out `shouldReturn` "an existing file"

    it
        "refuses a symbolic link as the file, and leaves its target untouched"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-create"
        $ \dir -> do
            keys <- two
            key <- signingKeyFile dir
            let target = dir </> "target"
                out = dir </> "link.age"
            BS.writeFile target "the target"
            createSymbolicLink target out
            options <- createOptionsFor key out keys
            runVaultCreate refusingPluginUi options
                >>= (`shouldSatisfy` either (const True) (const False))
            BS.readFile target `shouldReturn` "the target"
            -- control: a dangling link is refused too, and nothing appears
            let dangling = dir </> "dangling.age"
            createSymbolicLink (dir </> "nowhere") dangling
            danglingOptions <- createOptionsFor key dangling keys
            runVaultCreate refusingPluginUi danglingOptions
                >>= (`shouldSatisfy` either (const True) (const False))
            doesPathExist (dir </> "nowhere") `shouldReturn` False

    it "writes nothing when the plugin fails" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-create" $ \dir -> do
                keys <- two
                key <- signingKeyFile dir
                let out = dir </> "vault.age"
                options <- createOptionsFor key out keys
                result <-
                    steered [("CWT_FAKE_FIDO2_ERROR", "no authenticator")] $
                        runVaultCreate refusingPluginUi options
                result `shouldSatisfy` isLeftContaining "no authenticator"
                doesPathExist out `shouldReturn` False
                listDirectory dir >>= (`shouldBe` ["payment.skey"])

    it
        "names the plugin binary and writes nothing when it is not on the PATH"
        $ do
            keys <- withFakePlugins ["fido2-hmac"] two
            withTempDir "fido2-create" $ \dir -> do
                key <- signingKeyFile dir
                let out = dir </> "vault.age"
                options <- createOptionsFor key out keys
                result <-
                    withPathOnly ["/nonexistent"] $
                        runVaultCreate refusingPluginUi options
                result `shouldSatisfy` isLeftContaining "age-plugin-fido2-hmac"
                doesPathExist out `shouldReturn` False

    it
        "refuses a file that is not a signing key, naming it, without the key"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-create"
        $ \dir -> do
            keys <- two
            let key = dir </> "not-a-key"
                out = dir </> "vault.age"
            BS.writeFile key "just some words"
            options <- createOptionsFor key out keys
            result <- runVaultCreate refusingPluginUi options
            result `shouldSatisfy` isLeftContaining "signing key"
            doesPathExist out `shouldReturn` False

    it "never puts the signing key in a refusal" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-create" $ \dir -> do
                keys <- two
                key <- signingKeyFile dir
                let existing = dir </> "taken"
                BS.writeFile existing "taken"
                forM_
                    [ ([("CWT_FAKE_FIDO2_ERROR", "no authenticator")], dir </> "a.age")
                    , ([], existing)
                    ]
                    $ \(environment, out) -> do
                        options <- createOptionsFor key out keys
                        result <-
                            steered environment (runVaultCreate refusingPluginUi options)
                        case result of
                            Left line ->
                                TE.encodeUtf8 line
                                    `shouldSatisfy` (not . BS.isInfixOf seedHex)
                            Right () ->
                                if null environment
                                    then pure ()
                                    else expectationFailure "expected a refusal"

    it
        "reads the secret the plugin asks for through the interface it is given"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-create"
        $ \dir -> do
            keys <- two
            key <- signingKeyFile dir
            let out = dir </> "vault.age"
            options <- createOptionsFor key out keys
            (ui, events) <- recordingUi noAnswers{answerSecret = Just "654321"}
            result <-
                steered
                    [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN")
                    , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", "654321")
                    ]
                    $ runVaultCreate ui options
            result `shouldBe` Right ()
            events `shouldReturn` [AskedSecret "PIN"]
  where
    two = do
        alice <- fakeKeypair "fido2-hmac" "alice"
        bob <- fakeKeypair "fido2-hmac" "bob"
        pure (alice :| [bob])
    isLeftContaining needle = \case
        Left line -> needle `T.isInfixOf` line
        Right _ -> False

-- | A simulated person at the terminal, typing one line when the prompt asked for appears.
typedAt
    :: Handle
    -> Fd
    -> ByteString
    -> ByteString
    -> IO a
    -> IO (a, ByteString, Bool)
typedAt master slaveFd wanted line action = do
    result <- newEmptyMVar
    _ <- forkIO (try @SomeException action >>= putMVar result)
    prompt <- awaitPrompt master wanted
    echoing <- echoIsOn slaveFd
    BS.hPut master (line <> "\n") >> hFlush master
    outcome <- within (takeMVar result)
    rest <- drain master
    case outcome of
        Left e -> throwIO e
        Right a -> pure (a, prompt <> rest, echoing)

{- | The output on the master end until it holds the prompt asked for; no
prompt in time is a failure. A line break the terminal printed on its way
to the prompt does not count as the prompt.
-}
awaitPrompt :: Handle -> ByteString -> IO ByteString
awaitPrompt master wanted = go (1000 :: Int) BS.empty
  where
    go 0 seen =
        ioError . userError $
            "no prompt " <> show wanted <> " reached the terminal: " <> show seen
    go n seen = do
        out <- drain master
        let accumulated = seen <> out
        if wanted `BS.isInfixOf` accumulated
            then pure accumulated
            else threadDelay 5000 >> go (n - 1) accumulated

terminalInterface :: Spec
terminalInterface = describe "terminal interface" $ do
    it
        "reads a secret from the terminal with the echo off, and prints it nowhere"
        $ withPseudoTerminal
        $ \master slave slaveFd ->
            withTempDir "ui" $ \dir -> do
                setEchoOn slaveFd
                let messages = dir </> "messages"
                withFile messages WriteMode $ \messageHandle -> do
                    let ui = pluginUiOn slaveFd slave messageHandle
                    (secret, transcript, echoing) <-
                        typedAt master slaveFd "PIN for your key" "needle-pin-4471" $
                            uiRequestSecret ui "PIN for your key"
                    secret `shouldBe` Just "needle-pin-4471"
                    echoing `shouldBe` False
                    transcript `shouldSatisfy` BS.isInfixOf "PIN for your key"
                    transcript `shouldSatisfy` (not . BS.isInfixOf "needle-pin-4471")
                    echoIsOn slaveFd `shouldReturn` True
                BS.readFile messages
                    >>= (`shouldSatisfy` (not . BS.isInfixOf "needle-pin-4471"))

    it
        "serves the production interface from the controlling terminal of its process"
        $ withTempDir "ui-production"
        $ \dir -> do
            (masterFd, slaveFd) <- openPseudoTerminal
            slaveName <- getSlaveTerminalName masterFd
            master <- fdToHandle masterFd
            setEchoOn slaveFd
            let answers = dir </> "answers"
                messages = dir </> "stderr"
            -- a child process in a session of its own whose controlling
            -- terminal is the pseudo-terminal, which is what /dev/tty
            -- means to cwt
            child <- forkProcess $ do
                _ <- createSession
                closeFd masterFd
                closeFd slaveFd
                _ <- openFd slaveName ReadWrite defaultFileFlags
                target <-
                    openFd
                        messages
                        WriteOnly
                        defaultFileFlags{creat = Just 0o600}
                _ <- dupTo target stdError
                secret <- uiRequestSecret terminalPluginUi "PIN for your key"
                public <- uiRequestPublic terminalPluginUi "Which credential?"
                chosen <-
                    uiConfirm terminalPluginUi "Insert the key" "yes" (Just "no")
                uiMessage terminalPluginUi "touch your key"
                BS.writeFile answers $
                    BC.unlines
                        [ fromMaybe "refused" secret
                        , maybe "refused" TE.encodeUtf8 public
                        , BC.pack (show chosen)
                        ]
                exitImmediately ExitSuccess
            let user wanted typed = do
                    prompt <- awaitPrompt master wanted
                    echoing <- echoIsOn slaveFd
                    BS.hPut master (typed <> "\n") >> hFlush master
                    pure (prompt, echoing)
            (pinPrompt, pinEcho) <- user "PIN for your key" "needle-pin-8813"
            (credentialPrompt, credentialEcho) <-
                user "Which credential?" "credential 7"
            (confirmPrompt, _) <- user "Insert the key" "yes"
            status <- within (getProcessStatus True False child)
            status `shouldBe` Just (Exited ExitSuccess)
            rest <- drain master
            BS.readFile answers
                `shouldReturn` "needle-pin-8813\ncredential 7\nJust True\n"
            pinPrompt `shouldSatisfy` BS.isInfixOf "PIN for your key"
            credentialPrompt `shouldSatisfy` BS.isInfixOf "Which credential?"
            confirmPrompt `shouldSatisfy` BS.isInfixOf "Insert the key"
            -- the secret was typed with the echo off, the public value with it on
            (pinEcho, credentialEcho) `shouldBe` (False, True)
            forM_ [pinPrompt, rest] $ \seen ->
                seen `shouldSatisfy` (not . BS.isInfixOf "needle-pin-8813")
            seenOnStderr <- BS.readFile messages
            seenOnStderr `shouldSatisfy` BS.isInfixOf "touch your key"
            seenOnStderr `shouldSatisfy` (not . BS.isInfixOf "needle-pin-8813")

    it "echoes the same line when the echo is left on (control)" $
        withPseudoTerminal $ \master slave _ -> do
            BS.hPut master "needle-pin-4471\n" >> hFlush master
            line <- within (BC.hGetLine slave)
            line `shouldSatisfy` BS.isPrefixOf "needle-pin-4471"
            drain master >>= (`shouldSatisfy` BS.isInfixOf "needle-pin-4471")

    it "reads a public value from the terminal, echoed" $
        withPseudoTerminal $ \master slave slaveFd ->
            withTempDir "ui" $ \dir -> do
                setEchoOn slaveFd
                withFile (dir </> "messages") WriteMode $ \messageHandle -> do
                    let ui = pluginUiOn slaveFd slave messageHandle
                    (value, _, echoing) <-
                        typedAt master slaveFd "Which credential?" "credential 7" $
                            uiRequestPublic ui "Which credential?"
                    value `shouldBe` Just "credential 7"
                    echoing `shouldBe` True

    it "shows a message on the message handle, not on the terminal" $
        withPseudoTerminal $ \master slave slaveFd ->
            withTempDir "ui" $ \dir -> do
                let messages = dir </> "messages"
                withFile messages WriteMode $ \messageHandle ->
                    uiMessage (pluginUiOn slaveFd slave messageHandle) "touch your key"
                BS.readFile messages
                    >>= (`shouldSatisfy` BS.isInfixOf "touch your key")
                drain master
                    >>= (`shouldSatisfy` (not . BS.isInfixOf "touch your key"))

    it
        "reads a confirmation: the offered choices, and a refusal of anything else"
        $ forM_
            [ ("yes", Just True)
            , ("no", Just False)
            , ("maybe", Nothing)
            ]
        $ \(typed, expected) ->
            withPseudoTerminal $ \master slave slaveFd ->
                withTempDir "ui" $ \dir ->
                    withFile (dir </> "messages") WriteMode $ \messageHandle -> do
                        let ui = pluginUiOn slaveFd slave messageHandle
                        (answer, transcript, _) <-
                            typedAt master slaveFd "Insert the key" typed $
                                uiConfirm ui "Insert the key" "yes" (Just "no")
                        answer `shouldBe` expected
                        transcript `shouldSatisfy` BS.isInfixOf "Insert the key"

    it
        "reads a secret from the terminal only: from none in a session without one"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-tty"
        $ \dir -> do
            alice <- fakeKeypair "fido2-hmac" "alice"
            key <- signingKeyFile dir
            let create target =
                    [ "vault"
                    , "create"
                    , "--fido2"
                    , "--signing-key"
                    , key
                    , "--out"
                    , target
                    , "--recipient"
                    , T.unpack (keypairRecipient alice)
                    ]
                asking =
                    [ ("CWT_FAKE_FIDO2_SECRET_PROMPT", "PIN")
                    , ("CWT_FAKE_FIDO2_SECRET_EXPECTED", "needle-pin-5502")
                    ]
                out = dir </> "vault.age"
            -- control: a plugin that asks for nothing is served in the
            -- same session, so the session itself is not what fails
            (calmCode, _, calmErr) <-
                runCwtDetached (create (dir </> "calm.age")) ""
            (calmCode, calmErr) `shouldBe` (ExitSuccess, "")
            doesPathExist (dir </> "calm.age") `shouldReturn` True
            -- the secret is on stdin and in the environment, where a
            -- wrong client might look; the right one reads /dev/tty only
            (code, stdout, stderr) <-
                steered asking $
                    runCwtDetached (create out) "needle-pin-5502\n"
            code `shouldNotBe` ExitSuccess
            doesPathExist out `shouldReturn` False
            forM_ [stdout, stderr] $ \text ->
                text `shouldSatisfy` (not . isInfixOfS "needle-pin-5502")
            stderr `shouldSatisfy` (not . null)
  where
    isInfixOfS needle haystack = T.pack needle `T.isInfixOf` T.pack haystack

-- | Run @cwt@ in a session of its own, without a controlling terminal.
runCwtDetached :: [String] -> String -> IO (ExitCode, String, String)
runCwtDetached args input = do
    cwt <- cwtExecutable
    readCreateProcessWithExitCode
        (proc cwt args){new_session = True}
        input

-- | Run @cwt@ with arguments and stdin; exit code, stdout, stderr.
runCwt :: [String] -> String -> IO (ExitCode, String, String)
runCwt args input = do
    cwt <- cwtExecutable
    readCreateProcessWithExitCode (proc cwt args) input

throughTheProgram :: Spec
throughTheProgram = describe "the cwt program" $ do
    it "creates a vault with vault create --fido2" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-cwt" $ \dir -> do
                keys@(alice :| [bob]) <- twoKeys
                key <- signingKeyFile dir
                let vault = dir </> "vault.age"
                (code, out, err) <-
                    runCwt
                        ( [ "vault"
                          , "create"
                          , "--fido2"
                          , "--signing-key"
                          , key
                          , "--out"
                          , vault
                          ]
                            <> recipientFlags keys
                        )
                        ""
                (code, out, err) `shouldBe` (ExitSuccess, "", "")
                bytes <- BS.readFile vault
                forM_ [alice, bob] $ \pair ->
                    openedBy pair bytes >>= (`sameKey` plainKey (0x91 :: Int))

    it
        "refuses with a line on stderr and a non-zero status, saying nothing of a key"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-cwt"
        $ \dir -> do
            keys <- twoKeys
            key <- signingKeyFile dir
            let vault = dir </> "vault.age"
            BS.writeFile vault "taken"
            (code, out, err) <-
                runCwt
                    ( [ "vault"
                      , "create"
                      , "--fido2"
                      , "--signing-key"
                      , key
                      , "--out"
                      , vault
                      ]
                        <> recipientFlags keys
                    )
                    ""
            code `shouldNotBe` ExitSuccess
            out `shouldBe` ""
            length (lines err) `shouldBe` 1
            err `shouldSatisfy` (not . isInfixOfS (BC.unpack seedHex))
            BS.readFile vault `shouldReturn` "taken"

    it "shows a message of the plugin on stderr and never on stdout" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-cwt" $ \dir -> do
                keys <- twoKeys
                key <- signingKeyFile dir
                (code, out, err) <-
                    steered [("CWT_FAKE_FIDO2_MESSAGE", "touch your key")] $
                        runCwt
                            ( [ "vault"
                              , "create"
                              , "--fido2"
                              , "--signing-key"
                              , key
                              , "--out"
                              , dir </> "vault.age"
                              ]
                                <> recipientFlags keys
                            )
                            ""
                code `shouldBe` ExitSuccess
                out `shouldBe` ""
                err `shouldSatisfy` isInfixOfS "touch your key"
  where
    twoKeys = do
        alice <- fakeKeypair "fido2-hmac" "alice"
        bob <- fakeKeypair "fido2-hmac" "bob"
        pure (alice :| [bob])
    recipientFlags keys =
        concat
            [["--recipient", T.unpack (keypairRecipient k)] | k <- NE.toList keys]
    isInfixOfS needle haystack = T.pack needle `T.isInfixOf` T.pack haystack

rekeying :: Spec
rekeying = do
    it
        "rekeys through the cwt program: vault rekey writes the new set and leaves the old file"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-cwt"
        $ \dir -> do
            old@(alice :| [bob]) <- twoKeys
            carol :| _ <- (:| []) <$> fakeKeypair "fido2-hmac" "carol"
            vault <- createdVault dir old
            identity <- identityFileFor dir (alice :| [])
            kept <- BS.readFile vault
            let renewed = dir </> "renewed.age"
            (code, out, err) <-
                runCwt
                    ( [ "vault"
                      , "rekey"
                      , "--vault"
                      , vault
                      , "--fido2-identity"
                      , identity
                      , "--out"
                      , renewed
                      ]
                        <> concat
                            [ ["--recipient", T.unpack (keypairRecipient k)]
                            | k <- [carol, bob]
                            ]
                    )
                    ""
            (code, out, err) `shouldBe` (ExitSuccess, "", "")
            BS.readFile vault `shouldReturn` kept
            bytes <- BS.readFile renewed
            forM_ [carol, bob] $ \pair ->
                openedBy pair bytes >>= (`sameKey` plainKey (0x91 :: Int))
            openedBy alice bytes >>= (`shouldSatisfy` isNotOpened)

    it
        "writes the same key to a new set, mode 0600, and leaves the old file as it was"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-rekey"
        $ \dir -> do
            old@(alice :| [bob]) <- twoKeys
            new@(carol :| [dave]) <-
                (\a b -> a :| [b])
                    <$> fakeKeypair "fido2-hmac" "carol"
                    <*> fakeKeypair "fido2-hmac" "dave"
            vault <- createdVault dir old
            identity <- identityFileFor dir (alice :| [])
            kept <- BS.readFile vault
            let out = dir </> "new.age"
            options <- rekeyOptionsFor vault identity out new
            runVaultRekey refusingPluginUi options `shouldReturn` Right ()
            BS.readFile vault `shouldReturn` kept
            mode <- (.&. 0o777) . fileMode <$> getFileStatus out
            mode `shouldBe` 0o600
            rekeyed <- BS.readFile out
            forM_ [carol, dave] $ \pair ->
                openedBy pair rekeyed >>= (`sameKey` plainKey (0x91 :: Int))
            forM_ [alice, bob] $ \pair ->
                openedBy pair rekeyed >>= (`shouldSatisfy` isNotOpened)

    it
        "refuses an existing file, itself included, and leaves both untouched"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-rekey"
        $ \dir -> do
            old@(alice :| _) <- twoKeys
            vault <- createdVault dir old
            identity <- identityFileFor dir (alice :| [])
            kept <- BS.readFile vault
            let taken = dir </> "taken.age"
            BS.writeFile taken "taken"
            forM_ [vault, taken] $ \out -> do
                options <- rekeyOptionsFor vault identity out old
                result <- runVaultRekey refusingPluginUi options
                result
                    `shouldSatisfy` either (T.isInfixOf "already exists") (const False)
            BS.readFile vault `shouldReturn` kept
            BS.readFile taken `shouldReturn` "taken"

    it "writes nothing when the identity is not one of the vault's" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-rekey" $ \dir -> do
                old <- twoKeys
                carol :| _ <- (:| []) <$> fakeKeypair "fido2-hmac" "carol"
                vault <- createdVault dir old
                identity <- identityFileFor dir (carol :| [])
                let out = dir </> "new.age"
                options <- rekeyOptionsFor vault identity out (carol :| [])
                result <- runVaultRekey refusingPluginUi options
                result `shouldSatisfy` either (const True) (const False)
                doesPathExist out `shouldReturn` False

    it "writes nothing when the plugin fails, in either of its two phases" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-rekey" $ \dir -> do
                old@(alice :| _) <- twoKeys
                vault <- createdVault dir old
                identity <- identityFileFor dir (alice :| [])
                kept <- BS.readFile vault
                -- control: unsteered, the same command writes the new vault
                let renewed = dir </> "renewed.age"
                renewedOptions <- rekeyOptionsFor vault identity renewed old
                runVaultRekey refusingPluginUi renewedOptions
                    `shouldReturn` Right ()
                doesPathExist renewed `shouldReturn` True
                forM_ ["identity-v1", "recipient-v1"] $ \phase -> do
                    let out = dir </> (phase <> ".age")
                    options <- rekeyOptionsFor vault identity out old
                    result <-
                        steered
                            [ ("CWT_FAKE_FIDO2_ERROR", "no authenticator")
                            , ("CWT_FAKE_FIDO2_ONLY_IN", phase)
                            ]
                            $ runVaultRekey refusingPluginUi options
                    result `shouldSatisfy` either (const True) (const False)
                    -- the wrapping phase says what the plugin said; the opening
                    -- phase answers the one opening refusal
                    result
                        `shouldSatisfy` either
                            ( \line ->
                                ("no authenticator" `T.isInfixOf` line)
                                    == (phase == "recipient-v1")
                            )
                            (const False)
                    doesPathExist out `shouldReturn` False
                BS.readFile vault `shouldReturn` kept

    it "refuses a vault or an identity file it cannot read, naming it" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-rekey" $ \dir -> do
                old@(alice :| _) <- twoKeys
                vault <- createdVault dir old
                identity <- identityFileFor dir (alice :| [])
                let out = dir </> "new.age"
                missingVault <-
                    rekeyOptionsFor (dir </> "missing.age") identity out old
                runVaultRekey refusingPluginUi missingVault
                    >>= (`shouldSatisfy` either (T.isInfixOf "missing.age") (const False))
                missingIdentity <-
                    rekeyOptionsFor vault (dir </> "missing-id") out old
                runVaultRekey refusingPluginUi missingIdentity
                    >>= (`shouldSatisfy` either (T.isInfixOf "missing-id") (const False))
                doesPathExist out `shouldReturn` False
  where
    twoKeys = do
        alice <- fakeKeypair "fido2-hmac" "alice"
        bob <- fakeKeypair "fido2-hmac" "bob"
        pure (alice :| [bob])

goldenWitness :: Spec
goldenWitness = do
    it
        "gives the cardano-cli witness from a vault made by create, with each identity alone"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-golden"
        $ \dir -> do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            let keys = alice :| [bob]
                out = dir </> "vault.age"
            options <-
                createOptionsFor (fixturePath "golden/payment.skey") out keys
            runVaultCreate refusingPluginUi options `shouldReturn` Right ()
            expected <- readHexFixture "golden/witness.expected.hex"
            body <- goldenBody
            forM_ [alice, bob] $ \pair -> do
                identity <- identityFileFor dir (pair :| [])
                signer <-
                    loadSignerFromFido2
                        refusingPluginUi
                        (Fido2KeySource out identity)
                        >>= either (fail . T.unpack) pure
                witness <- signTxBody signer body
                encodeDetachedWitness witness `shouldBe` expected

    it "attaches to the transaction cardano-cli signed, byte for byte" $
        withFakePlugins ["fido2-hmac"] $
            withTempDir "fido2-golden" $ \dir -> do
                alice <- fakeKeypair "fido2-hmac" "alice"
                let out = dir </> "vault.age"
                options <-
                    createOptionsFor (fixturePath "golden/payment.skey") out (alice :| [])
                runVaultCreate refusingPluginUi options `shouldReturn` Right ()
                identity <- identityFileFor dir (alice :| [])
                signer <-
                    loadSignerFromFido2
                        refusingPluginUi
                        (Fido2KeySource out identity)
                        >>= either (fail . T.unpack) pure
                unsigned <- readHexFixture "golden/unsigned.cbor.hex"
                signed <- readHexFixture "golden/signed.expected.cbor.hex"
                body <- goldenBody
                witness <- signTxBody signer body
                attachWitnesses [witness] unsigned `shouldBe` Right signed

    it
        "refuses to sign with an identity that is not the vault's, in one line"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-golden"
        $ \dir -> do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            let out = dir </> "vault.age"
            options <-
                createOptionsFor (fixturePath "golden/payment.skey") out (alice :| [])
            runVaultCreate refusingPluginUi options `shouldReturn` Right ()
            identity <- identityFileFor dir (bob :| [])
            result <-
                loadSignerFromFido2 refusingPluginUi (Fido2KeySource out identity)
            case result of
                Left line -> do
                    line `shouldSatisfy` (not . T.null)
                    T.any (== '\n') line `shouldBe` False
                Right _ -> expectationFailure "expected a refusal"

    it
        "signs the golden transaction through the cwt program, byte for byte"
        $ withFakePlugins ["fido2-hmac"]
        $ withTempDir "fido2-golden"
        $ \dir -> do
            alice <- fakeKeypair "fido2-hmac" "alice"
            bob <- fakeKeypair "fido2-hmac" "bob"
            let out = dir </> "vault.age"
            (createCode, _, _) <-
                runCwt'
                    [ "vault"
                    , "create"
                    , "--fido2"
                    , "--signing-key"
                    , fixturePath "golden/payment.skey"
                    , "--out"
                    , out
                    , "--recipient"
                    , T.unpack (keypairRecipient alice)
                    , "--recipient"
                    , T.unpack (keypairRecipient bob)
                    ]
                    ""
            createCode `shouldBe` ExitSuccess
            unsigned <- readFixture "golden/unsigned.cbor.hex"
            signed <- readFixture "golden/signed.expected.cbor.hex"
            forM_ [alice, bob] $ \pair -> do
                identity <- identityFileFor dir (pair :| [])
                (code, stdout, stderr) <-
                    runCwt'
                        [ "sign"
                        , "--fido2-vault"
                        , out
                        , "--fido2-identity"
                        , identity
                        ]
                        (BC.unpack unsigned)
                (code, stderr) `shouldBe` (ExitSuccess, "")
                BC.strip (BC.pack stdout) `shouldBe` BC.strip signed
  where
    runCwt' args input = do
        cwt <- cwtExecutable
        readCreateProcessWithExitCode (proc cwt args) input
    goldenBody =
        readHexFixture "golden/unsigned.cbor.hex"
            >>= either (fail . show) pure . transactionBodyBytes
