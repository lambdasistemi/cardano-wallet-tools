{- |
Module      : Support.FakePlugin
Description : The fake age plugin on the specs' own PATH, and what drives it
License     : Apache-2.0

The specs never reach a real plugin or a real authenticator. The fake
plugin is a program of this repository that speaks the age plugin stdio
protocol; here it is linked under plugin names in a directory of the
spec's own and put first on the @PATH@ for the length of one example.

Everything a spec compares against comes from a producer at run time:
keys from the fake's own @--keygen@, plaintext and stanzas from stock
@age@ and from the age library's header parser. Nothing is typed beside
the assertion.

A missing fake plugin or a missing stock @age@ fails the example by
name; no example here skips.
-}
module Support.FakePlugin
    ( -- * The fake and its keys
      fakePluginExecutable
    , cwtExecutable
    , Keypair (..)
    , fakeKeypair
    , identityFileBytes

      -- * On the PATH
    , withFakePlugins
    , withPathOnly

      -- * Steering and logging
    , steered
    , loggedPlugin

      -- * The protocol, driven by hand
    , Exchange (..)
    , converse
    , okReply
    , unsupportedReply

      -- * Stock age
    , ageDecryptWithIdentity
    , ageEncryptToRecipients

      -- * Age files
    , stanzaTagsOf
    , stanzaCountOf
    ) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (IOException, try)
import Control.Monad (forM_, unless)
import Crypto.Age.Header
    ( Header (..)
    , Stanza (..)
    , headerParser
    , stanzaBuilder
    , stanzaParser
    )
import Data.Attoparsec.ByteString (IResult (..), parse, parseWith)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Builder qualified as Builder
import Data.ByteString.Char8 qualified as BC
import Data.ByteString.Lazy qualified as BSL
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.List (intercalate)
import Data.List.NonEmpty qualified as NE
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.Vault (withEnv, withTempDir)
import System.Directory (findExecutable, makeAbsolute)
import System.Environment (lookupEnv)
import System.Exit (ExitCode (..))
import System.FilePath ((</>))
import System.IO
    ( BufferMode (NoBuffering)
    , Handle
    , hClose
    , hFlush
    , hSetBinaryMode
    , hSetBuffering
    )
import System.Posix.Files (createSymbolicLink)
import System.Process
    ( CreateProcess (..)
    , StdStream (..)
    , createProcess
    , proc
    , readCreateProcessWithExitCode
    , waitForProcess
    )
import System.Timeout (timeout)

-- * The fake and its keys

-- | A built program of this package, found on the PATH; absence fails.
builtProgram :: String -> IO FilePath
builtProgram name = do
    found <- findExecutable name
    case found of
        Just path -> makeAbsolute path
        Nothing ->
            fail
                ( name
                    <> " is not on the PATH: the specs need it and never skip"
                    <> " (run them through cabal test, nix run .#unit-tests"
                    <> " or nix build .#checks.<system>.unit)"
                )

-- | The fake plugin program, found on the PATH.
fakePluginExecutable :: IO FilePath
fakePluginExecutable = builtProgram "cwt-fake-fido2-plugin"

-- | The @cwt@ program, found on the PATH.
cwtExecutable :: IO FilePath
cwtExecutable = builtProgram "cwt"

-- | A recipient and its identity, as the fake made them.
data Keypair = Keypair
    { keypairRecipient :: Text
    , keypairIdentity :: Text
    }

instance Show Keypair where
    show Keypair{keypairRecipient} =
        "Keypair " <> T.unpack keypairRecipient

{- | A key pair for a plugin name and a label, from the fake's own
generator. The same label gives the same pair.
-}
fakeKeypair :: String -> String -> IO Keypair
fakeKeypair name label = do
    exe <- fakePluginExecutable
    (code, out, err) <-
        readCreateProcessWithExitCode
            (proc exe ["--keygen", name, label])
            ""
    case (code, lines out) of
        (ExitSuccess, [recipient, identity]) ->
            pure (Keypair (T.pack recipient) (T.pack identity))
        _ -> fail ("the fake plugin made no key: " <> show code <> " " <> err)

-- | An identity file holding the identities, with a comment first.
identityFileBytes :: [Keypair] -> ByteString
identityFileBytes pairs =
    "# identities for the specs\n"
        <> BS.concat
            [TE.encodeUtf8 (keypairIdentity k) <> "\n" | k <- pairs]

-- * On the PATH

{- | Run an action with the fake plugin linked under each plugin name
(@age-plugin-NAME@) in a directory of its own, first on the @PATH@.
-}
withFakePlugins :: [String] -> IO a -> IO a
withFakePlugins names action = do
    exe <- fakePluginExecutable
    withTempDir "fake-plugins" $ \dir -> do
        forM_ names $ \name ->
            createSymbolicLink exe (dir </> ("age-plugin-" <> name))
        old <- fromMaybe "" <$> lookupEnv "PATH"
        withEnv [("PATH", dir <> ":" <> old)] action

-- | Run an action with exactly these directories as the @PATH@.
withPathOnly :: [FilePath] -> IO a -> IO a
withPathOnly dirs = withEnv [("PATH", intercalate ":" dirs)]

-- * Steering and logging

-- | Steer the fake with environment variables for one action.
steered :: [(String, String)] -> IO a -> IO a
steered = withEnv

{- | Run an action with the fake logging into a fresh file; the action's
result and the lines the fake logged.
-}
loggedPlugin :: IO a -> IO (a, [String])
loggedPlugin action = withTempDir "plugin-log" $ \dir -> do
    let path = dir </> "log"
    BS.writeFile path ""
    result <- withEnv [("CWT_FAKE_FIDO2_LOG", path)] action
    logged <- BS.readFile path
    pure (result, lines (BC.unpack logged))

-- * The protocol, driven by hand

-- | What a plugin sent, and how it ended.
data Exchange = Exchange
    { exchangeSent :: [Stanza]
    -- ^ every command the plugin sent, @done@ included
    , exchangeExit :: ExitCode
    }

-- | The reply @ok@ with no data.
okReply :: Stanza
okReply = Stanza{sTag = "ok", sArgs = [], sBody = ""}

-- | The reply @unsupported@.
unsupportedReply :: Stanza
unsupportedReply = Stanza{sTag = "unsupported", sArgs = [], sBody = ""}

{- | Drive a plugin by hand: start it under the given path with the
state machine, send the first phase and @done@, then answer each command
it sends until its @done@ or the end of its output.
-}
converse
    :: FilePath
    -> String
    -> [Stanza]
    -> (Stanza -> Stanza)
    -> IO Exchange
converse exe machine phase answer = do
    (Just stdinH, Just stdoutH, _, process) <-
        createProcess
            (proc exe ["--age-plugin=" <> machine])
                { std_in = CreatePipe
                , std_out = CreatePipe
                }
    hSetBinaryMode stdinH True
    hSetBinaryMode stdoutH True
    hSetBuffering stdinH NoBuffering
    leftover <- newIORef BS.empty
    let nextStanza = do
            pending <- readIORef leftover
            result <-
                parseWith (BS.hGetSome stdoutH 4096) stanzaParser pending
            case result of
                Done rest s -> writeIORef leftover rest >> pure (Just s)
                _ -> pure Nothing
        loop = do
            next <- nextStanza
            case next of
                Nothing -> pure []
                Just s
                    | sTag s == "done" -> pure [s]
                    | otherwise -> do
                        sendStanza stdinH (answer s)
                        (s :) <$> loop
    forM_
        (phase <> [Stanza{sTag = "done", sArgs = [], sBody = ""}])
        (sendStanza stdinH)
    sent <-
        timeout 30000000 loop
            >>= maybe (fail "the fake plugin stalled") pure
    hClose stdinH
    code <- waitForProcess process
    pure (Exchange sent code)

sendStanza :: Handle -> Stanza -> IO ()
sendStanza h s = do
    BS.hPut h (BSL.toStrict (Builder.toLazyByteString (stanzaBuilder s)))
    hFlush h

-- * Stock age

{- | Stock @age -d -i@ over an identity file and a vault: exit code,
plaintext, stderr. A missing @age@ fails the example.
-}
ageDecryptWithIdentity
    :: ByteString -> ByteString -> IO (ExitCode, ByteString, String)
ageDecryptWithIdentity identities vault = withTempDir "age-id" $ \dir -> do
    let identityPath = dir </> "identities"
        vaultPath = dir </> "vault.age"
    BS.writeFile identityPath identities
    BS.writeFile vaultPath vault
    (code, out, err) <-
        stockAge ["-d", "-i", identityPath, vaultPath]
    pure (code, out, BC.unpack err)

{- | Stock @age -r@ to the recipients, over a plaintext: the age file it
made. A failure of stock @age@ fails the example.
-}
ageEncryptToRecipients :: [Text] -> ByteString -> IO ByteString
ageEncryptToRecipients recipients plaintext =
    withTempDir "age-enc" $ \dir -> do
        let inputPath = dir </> "plaintext"
            outputPath = dir </> "out.age"
        BS.writeFile inputPath plaintext
        (code, _, err) <-
            stockAge
                ( concat [["-r", T.unpack r] | r <- recipients]
                    <> ["-o", outputPath, inputPath]
                )
        unless (code == ExitSuccess) $
            fail
                ("stock age could not encrypt: " <> show code <> " " <> BC.unpack err)
        BS.readFile outputPath

stockAge :: [String] -> IO (ExitCode, ByteString, ByteString)
stockAge args = do
    ran <- try (runBinary (proc "age" args))
    case ran of
        Left (e :: IOException) ->
            fail ("stock age could not be run (is age on PATH?): " <> show e)
        Right result -> pure result

-- | Run a program with no input; exit code, standard output and error as bytes.
runBinary :: CreateProcess -> IO (ExitCode, ByteString, ByteString)
runBinary process = do
    (_, stdoutH, stderrH, handle) <-
        createProcess
            process{std_in = NoStream, std_out = CreatePipe, std_err = CreatePipe}
    case (stdoutH, stderrH) of
        (Just out, Just err) -> do
            errors <- newEmptyMVar
            _ <- forkIO (BS.hGetContents err >>= putMVar errors)
            output <- BS.hGetContents out
            errorBytes <- takeMVar errors
            code <- waitForProcess handle
            pure (code, output, errorBytes)
        _ -> fail "the program has no output"

-- * Age files

-- | The tags of the stanzas of an age file's header, as the age library reads them.
stanzaTagsOf :: ByteString -> Either String [ByteString]
stanzaTagsOf file = case parse headerParser file of
    Done _ Header{hStanzas} -> Right (sTag <$> NE.toList hStanzas)
    Fail _ _ message -> Left message
    Partial _ -> Left "the header is not complete"

-- | The number of stanzas in an age file's header.
stanzaCountOf :: ByteString -> Either String Int
stanzaCountOf = fmap length . stanzaTagsOf
