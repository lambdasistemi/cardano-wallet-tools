{- |
Module      : Cardano.Wallet.Tools.Vault.Plugin.Process
Description : Finding a plugin binary and speaking stanzas to it
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A plugin is a child process named @age-plugin-NAME@ found on the
@PATH@, started with @--age-plugin=STATE_MACHINE@ and spoken to in age
stanzas on its standard input and output. Its standard error is the
terminal's. Directories that are not absolute are never searched, as the
age plugin specification requires, so a plugin dropped in the working
directory is not run.
-}
module Cardano.Wallet.Tools.Vault.Plugin.Process
    ( -- * Finding
      findPluginBinary

      -- * Running
    , Wire
    , withPlugin

      -- * Speaking
    , sendStanza
    , receiveStanza
    ) where

import Control.Exception (IOException, try)
import Crypto.Age.Header
    ( Stanza
    , stanzaBuilder
    , stanzaParser
    )
import Data.Attoparsec.ByteString (IResult (..), parseWith)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Builder qualified as Builder
import Data.ByteString.Lazy qualified as BSL
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import System.Environment (lookupEnv)
import System.Exit (ExitCode)
import System.FilePath
    ( isAbsolute
    , splitSearchPath
    , (</>)
    )
import System.IO
    ( BufferMode (NoBuffering)
    , Handle
    , hClose
    , hFlush
    , hSetBinaryMode
    , hSetBuffering
    )
import System.Posix.Files
    ( fileAccess
    , getFileStatus
    , isRegularFile
    )
import System.Process
    ( CreateProcess (..)
    , ProcessHandle
    , StdStream (..)
    , proc
    , terminateProcess
    , waitForProcess
    , withCreateProcess
    )
import System.Timeout (timeout)

-- | The first executable file of that name in an absolute @PATH@ entry.
findPluginBinary :: String -> IO (Maybe FilePath)
findPluginBinary binary = do
    searchPath <- fromMaybe "" <$> lookupEnv "PATH"
    firstExecutable
        [dir </> binary | dir <- splitSearchPath searchPath, isAbsolute dir]
  where
    firstExecutable [] = pure Nothing
    firstExecutable (candidate : more) = do
        found <- isExecutable candidate
        if found then pure (Just candidate) else firstExecutable more
    isExecutable path = do
        status <- try @IOException (getFileStatus path)
        case status of
            Right s | isRegularFile s -> fileAccess path False False True
            _ -> pure False

-- | The two ends of a plugin conversation, and what is read ahead.
data Wire = Wire
    { wireTo :: Handle
    , wireFrom :: Handle
    , wireAhead :: IORef ByteString
    }

{- | Start the plugin binary in a state machine, hand its conversation to
the action, then close its input and let it finish. A plugin that has
not exited a few seconds after its input closed is terminated: it has
said everything the client needs. The exit status is nothing for such a
plugin.
-}
withPlugin
    :: FilePath -> String -> (Wire -> IO a) -> IO (a, Maybe ExitCode)
withPlugin path stateMachine conversation =
    withCreateProcess
        (proc path ["--age-plugin=" <> stateMachine])
            { std_in = CreatePipe
            , std_out = CreatePipe
            }
        $ \toPlugin fromPlugin _ process -> case (toPlugin, fromPlugin) of
            (Just input, Just output) -> do
                hSetBinaryMode input True
                hSetBinaryMode output True
                hSetBuffering input NoBuffering
                ahead <- newIORef BS.empty
                result <- conversation (Wire input output ahead)
                _ <- try @IOException (hClose input)
                status <- finished process
                pure (result, status)
            _ -> ioError (userError "the plugin has no standard input or output")
  where
    finished :: ProcessHandle -> IO (Maybe ExitCode)
    finished process = do
        status <- timeout 5000000 (waitForProcess process)
        case status of
            Just _ -> pure status
            Nothing -> terminateProcess process >> pure Nothing

-- | Write a stanza to the plugin; nothing when the plugin has stopped reading.
sendStanza :: Wire -> Stanza -> IO Bool
sendStanza wire stanza = do
    written <-
        try @IOException $ do
            BS.hPut (wireTo wire) (toStrict (stanzaBuilder stanza))
            hFlush (wireTo wire)
    pure (either (const False) (const True) written)
  where
    toStrict = BSL.toStrict . Builder.toLazyByteString

{- | The next stanza the plugin wrote: nothing at the end of its output
or when what it wrote is no stanza.
-}
receiveStanza :: Wire -> IO (Maybe Stanza)
receiveStanza wire = do
    pending <- readIORef (wireAhead wire)
    parsed <-
        try @IOException $
            parseWith (BS.hGetSome (wireFrom wire) 4096) stanzaParser pending
    case parsed of
        Right (Done rest stanza) -> writeIORef (wireAhead wire) rest >> pure (Just stanza)
        _ -> pure Nothing
