{- |
Module      : Cardano.Wallet.Tools.Vault.Passphrase
Description : Reading a vault passphrase from a terminal or a descriptor
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A passphrase is a non-empty byte string held in memory for the length
of one command. It has no textual rendering that shows its content:
the 'Show' instance prints a fixed marker, and no refusal names it.

Two sources, one parser:

* a terminal prompt on @\/dev\/tty@ with echo disabled, a human typing;
* an inherited file descriptor (@--passphrase-fd N@) reading one line,
  a script. The descriptor source never asks for a confirmation, so a
  scripted creation reads the passphrase exactly once.

The passphrase is never accepted as a command-line argument, an
environment variable or a file path; the command layer owns that
boundary and passes a 'PassphraseSource' here.
-}
module Cardano.Wallet.Tools.Vault.Passphrase
    ( -- * Passphrase
      Passphrase
    , mkPassphrase
    , passphraseBytes
    , confirmPassphrase

      -- * Sources
    , PassphraseSource (..)
    , Confirmation (..)
    , readPassphrase
    , readTerminalPassphrase
    , withHiddenEcho

      -- * Refusals
    , PassphraseRefusal (..)
    , renderPassphraseRefusal
    ) where

import Control.Exception (IOException, bracket, bracket_, catch)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Functor ((<&>))
import Data.Text (Text)
import Data.Text qualified as T
import System.IO
    ( BufferMode (NoBuffering)
    , Handle
    , hClose
    , hFlush
    , hPutStr
    , hSetBuffering
    )
import System.Posix.IO
    ( OpenMode (ReadWrite)
    , defaultFileFlags
    , fdToHandle
    , openFd
    )
import System.Posix.Terminal
    ( TerminalMode (EnableEcho)
    , TerminalState (Immediately)
    , getTerminalAttributes
    , setTerminalAttributes
    , withoutMode
    )
import System.Posix.Types (Fd (..))

-- | A non-empty passphrase, compared by content and never shown.
newtype Passphrase = Passphrase ByteString
    deriving stock (Eq)

instance Show Passphrase where
    show _ = "<passphrase>"

-- | Where a passphrase is read from: the terminal, or a descriptor.
data PassphraseSource
    = -- | @\/dev\/tty@, echo disabled, the human path
      PassphraseTerminal
    | -- | an inherited descriptor, @--passphrase-fd N@, the script path
      PassphraseDescriptor Int
    deriving stock (Eq, Show)

-- | Whether a terminal read asks for the passphrase twice.
data Confirmation
    = -- | read the passphrase once, as an opening command does
      AskOnce
    | -- | read it twice and require agreement, as a creation does
      AskTwice
    deriving stock (Eq, Show)

-- | Why a passphrase could not be read. None names the passphrase.
data PassphraseRefusal
    = -- | the passphrase itself is empty
      PassphraseEmpty
    | -- | the two typed lines disagreed
      PassphraseConfirmationDiffers
    | -- | the given descriptor could not be read, naming its number
      PassphraseDescriptorUnreadable Int
    | -- | @\/dev\/tty@ could not be opened or read
      PassphraseTerminalUnavailable
    deriving stock (Eq, Show)

-- | The one place a passphrase is born from bytes: empty is refused.
mkPassphrase :: ByteString -> Either PassphraseRefusal Passphrase
mkPassphrase raw
    | BS.null raw = Left PassphraseEmpty
    | otherwise = Right (Passphrase raw)

-- | The passphrase's bytes, read by the vault's seal and open only.
passphraseBytes :: Passphrase -> ByteString
passphraseBytes (Passphrase bytes) = bytes

{- | The confirmation decision of a creation, pure so the mismatch rule
is checkable without a terminal.
-}
confirmPassphrase
    :: ByteString
    -- ^ first typed line
    -> ByteString
    -- ^ second typed line
    -> Either PassphraseRefusal Passphrase
confirmPassphrase first second
    | first /= second = Left PassphraseConfirmationDiffers
    | otherwise = mkPassphrase first

{- | Read a passphrase from the source. A terminal source honours the
confirmation; a descriptor source reads exactly one line whatever the
confirmation asks.
-}
readPassphrase
    :: Confirmation
    -> PassphraseSource
    -> IO (Either PassphraseRefusal Passphrase)
readPassphrase confirmation = \case
    PassphraseDescriptor n ->
        readDescriptorLine n <&> (>>= mkPassphrase . trimLine)
    PassphraseTerminal ->
        catch
            ( bracket
                openTerminal
                (hClose . snd)
                (uncurry (readTerminalPassphrase confirmation))
            )
            ( \(_ :: IOException) ->
                pure (Left PassphraseTerminalUnavailable)
            )

-- | @/dev/tty@ read and written without buffering, with its descriptor.
openTerminal :: IO (Fd, Handle)
openTerminal = do
    fd <- openFd "/dev/tty" ReadWrite defaultFileFlags
    handle <- fdToHandle fd
    hSetBuffering handle NoBuffering
    pure (fd, handle)

-- | One line from an inherited descriptor, or the refusal naming it.
readDescriptorLine :: Int -> IO (Either PassphraseRefusal ByteString)
readDescriptorLine n =
    catch
        ( bracket
            (fdToHandle (Fd (fromIntegral n)))
            hClose
            (fmap Right . BC.hGetLine)
        )
        ( \(_ :: IOException) -> pure (Left (PassphraseDescriptorUnreadable n))
        )

-- | One line as typed: its trailing carriage return and line feed gone.
trimLine :: ByteString -> ByteString
trimLine = BC.dropWhileEnd (\c -> c == '\r' || c == '\n')

{- | Read a passphrase from a terminal the caller opened: echo off
before the first prompt byte is written, restored on every exit.
-}
readTerminalPassphrase
    :: Confirmation
    -> Fd
    -> Handle
    -> IO (Either PassphraseRefusal Passphrase)
readTerminalPassphrase confirmation fd handle = case confirmation of
    AskOnce -> mkPassphrase <$> typedLine "Vault passphrase: "
    AskTwice -> do
        first <- typedLine "New vault passphrase: "
        second <- typedLine "Confirm vault passphrase: "
        pure (confirmPassphrase first second)
  where
    -- the prompt is written inside the bracket, so no byte of it reaches
    -- a terminal whose echo is still on; the newline after the line is
    -- the prompt's own and never the typed text
    typedLine prompt = do
        line <- withHiddenEcho fd $ do
            hPutStr handle prompt
            hFlush handle
            BC.hGetLine handle
        hPutStr handle "\n"
        hFlush handle
        pure (trimLine line)

{- | Run an action with the terminal's echo off, restoring it on every
exit, the action throwing included.
-}
withHiddenEcho
    :: Fd
    -- ^ the terminal
    -> IO a
    -> IO a
withHiddenEcho fd action = do
    attributes <- getTerminalAttributes fd
    bracket_
        ( setTerminalAttributes
            fd
            (withoutMode attributes EnableEcho)
            Immediately
        )
        (setTerminalAttributes fd attributes Immediately)
        action

-- | One line naming the refusal, carrying no secret.
renderPassphraseRefusal :: PassphraseRefusal -> Text
renderPassphraseRefusal = \case
    PassphraseEmpty -> "the passphrase is empty"
    PassphraseConfirmationDiffers ->
        "the passphrase confirmation did not match"
    PassphraseDescriptorUnreadable n ->
        "cannot read the passphrase from descriptor " <> T.pack (show n)
    PassphraseTerminalUnavailable ->
        "cannot read a passphrase from the terminal"
