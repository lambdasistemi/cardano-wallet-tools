{- |
Module      : Cardano.Wallet.Tools.Cli.Fido2
Description : The FIDO2 vault commands of cwt: option parsers and handlers
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The command-line surface of the FIDO2 vault: @cwt vault create --fido2@,
@cwt vault rekey@, and the key source @--fido2-vault --fido2-identity@
of @cwt sign@. The plugin asks the person for a PIN or a touch through
the terminal: messages go to standard error, a secret is read from
@\/dev\/tty@ with the echo off, and nothing of a secret, a file key or a
signing key is printed.

The handlers refuse an existing output path before they contact any
authenticator, and write through the exclusive, mode 0600 vault file
creation, so a failing plugin leaves nothing behind.
-}
module Cardano.Wallet.Tools.Cli.Fido2
    ( -- * Terminal
      terminalPluginUi
    , pluginUiOn

      -- * Creating
    , VaultCreateOptions (..)
    , vaultCreateParser
    , runVaultCreate

      -- * Rekeying
    , VaultRekeyOptions (..)
    , vaultRekeyParser
    , runVaultRekey

      -- * Signing
    , Fido2KeySource (..)
    , fido2KeySourceParser
    , loadSignerFromFido2
    ) where

import Cardano.Wallet.Tools.Sign (Signer)
import Cardano.Wallet.Tools.Vault.Fido2
    ( openFido2Vault
    , parseFido2Identities
    , parseFido2Recipient
    , rekeyFido2Vault
    , renderFido2Refusal
    , sealFido2Vault
    )
import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , createVaultFile
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase (withHiddenEcho)
import Cardano.Wallet.Tools.Vault.Payload
    ( OpenedKey (..)
    , parseSigningKeyEnvelope
    , signerFromKey
    )
import Cardano.Wallet.Tools.Vault.Plugin (PluginUi (..))
import Control.Exception (IOException, bracket, try)
import Control.Monad (join, when)
import Control.Monad.Trans.Except (ExceptT (..), except, runExceptT)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Char (isControl)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Text.Encoding.Error (lenientDecode)
import Options.Applicative
import System.IO
    ( BufferMode (NoBuffering)
    , Handle
    , hClose
    , hFlush
    , hSetBuffering
    , stderr
    )
import System.IO.Error (tryIOError)
import System.Posix.Files (getSymbolicLinkStatus)
import System.Posix.IO
    ( OpenMode (ReadWrite)
    , defaultFileFlags
    , fdToHandle
    , openFd
    )
import System.Posix.Types (Fd)

-- | What @cwt vault create --fido2@ was asked to do.
data VaultCreateOptions = VaultCreateOptions
    { createRecipients :: NonEmpty Text
    -- ^ the @fido2-hmac@ recipients, at least one
    , createSigningKey :: FilePath
    -- ^ the plaintext signing key to seal
    , createOut :: FilePath
    -- ^ the vault file to create, which must not exist
    }
    deriving stock (Eq, Show)

-- | What @cwt vault rekey@ was asked to do.
data VaultRekeyOptions = VaultRekeyOptions
    { rekeyVault :: FilePath
    -- ^ the vault to read, which is not changed
    , rekeyIdentity :: FilePath
    -- ^ an identity file holding an identity of the vault
    , rekeyRecipients :: NonEmpty Text
    -- ^ the new set, at least one
    , rekeyOut :: FilePath
    -- ^ the vault file to create, which must not exist
    }
    deriving stock (Eq, Show)

-- | Where @cwt sign@ takes a FIDO2 vault and its identity from.
data Fido2KeySource = Fido2KeySource
    { fido2VaultPath :: FilePath
    , fido2IdentityPath :: FilePath
    }
    deriving stock (Eq, Show)

-- * Parsers

-- | @--fido2 --recipient R… --signing-key FILE --out FILE@.
vaultCreateParser :: Parser VaultCreateOptions
vaultCreateParser =
    VaultCreateOptions
        <$ flag'
            ()
            ( long "fido2"
                <> help "Seal to FIDO2 authenticators through the fido2-hmac age plugin"
            )
        <*> recipients
        <*> strOption
            ( long "signing-key"
                <> metavar "FILE"
                <> help "Plaintext signing key to seal"
            )
        <*> outOption

-- | @--vault FILE --fido2-identity FILE --recipient R… --out FILE@.
vaultRekeyParser :: Parser VaultRekeyOptions
vaultRekeyParser =
    VaultRekeyOptions
        <$> strOption
            ( long "vault"
                <> metavar "FILE"
                <> help "FIDO2 vault to read; it is not changed"
            )
        <*> identityOption
        <*> recipients
        <*> outOption

-- | @--fido2-vault FILE --fido2-identity FILE@.
fido2KeySourceParser :: Parser Fido2KeySource
fido2KeySourceParser =
    Fido2KeySource
        <$> strOption
            ( long "fido2-vault"
                <> metavar "FILE"
                <> help "Path to a FIDO2 signing key vault"
            )
        <*> identityOption

-- | One or more @--recipient@.
recipients :: Parser (NonEmpty Text)
recipients = (:|) <$> recipient <*> many recipient
  where
    recipient =
        T.pack
            <$> strOption
                ( long "recipient"
                    <> metavar "RECIPIENT"
                    <> help
                        "A fido2-hmac recipient (age1fido2-hmac1…); repeat for several"
                )

identityOption :: Parser FilePath
identityOption =
    strOption
        ( long "fido2-identity"
            <> metavar "FILE"
            <> help "An age identity file holding a fido2-hmac identity of the vault"
        )

outOption :: Parser FilePath
outOption =
    strOption
        ( long "out"
            <> metavar "FILE"
            <> help "Vault file to create; it must not exist"
        )

-- * Handlers

{- | Seal the key file to the recipients into a new vault file; the
refusal, rendered, on failure. The key is read and checked, the
recipients parsed and the output path found free before any plugin is
started.
-}
runVaultCreate
    :: PluginUi -> VaultCreateOptions -> IO (Either Text ())
runVaultCreate ui options = runExceptT $ do
    keyFile <- readBytes "signing key file" (createSigningKey options)
    key <-
        except . first (const notAKey) $
            parseSigningKeyEnvelope keyFile
    recipients' <-
        except . first renderFido2Refusal $
            traverse parseFido2Recipient (createRecipients options)
    ExceptT (outputFree (createOut options))
    vault <-
        ExceptT . fmap (first renderFido2Refusal) $
            sealFido2Vault ui recipients' key
    ExceptT . fmap (first renderVaultRefusal) $
        createVaultFile (createOut options) vault
  where
    notAKey =
        "not a payment signing key: " <> T.pack (createSigningKey options)

{- | Write the same key, sealed to a new set of recipients, into a new
vault file, opening the old vault with an identity of it. The old vault
is read and never written.
-}
runVaultRekey :: PluginUi -> VaultRekeyOptions -> IO (Either Text ())
runVaultRekey ui options = runExceptT $ do
    vault <- readBytes "vault file" (rekeyVault options)
    identityFile <- readBytes "identity file" (rekeyIdentity options)
    identities <-
        except . first renderFido2Refusal $
            parseFido2Identities identityFile
    recipients' <-
        except . first renderFido2Refusal $
            traverse parseFido2Recipient (rekeyRecipients options)
    ExceptT (outputFree (rekeyOut options))
    rekeyed <-
        ExceptT . fmap (first renderFido2Refusal) $
            rekeyFido2Vault ui identities recipients' vault
    ExceptT . fmap (first renderVaultRefusal) $
        createVaultFile (rekeyOut options) rekeyed

-- | The signer for a FIDO2 vault and identity; the refusal, rendered, on failure.
loadSignerFromFido2
    :: PluginUi -> Fido2KeySource -> IO (Either Text (Signer IO))
loadSignerFromFido2 ui source = runExceptT $ do
    vault <- readBytes "vault file" (fido2VaultPath source)
    identityFile <- readBytes "identity file" (fido2IdentityPath source)
    identities <-
        except . first renderFido2Refusal $
            parseFido2Identities identityFile
    opened <-
        ExceptT . fmap (first renderFido2Refusal) $
            openFido2Vault ui identities vault
    pure (signerFromKey (opened :: OpenedKey))

-- | The path must name nothing at all, a dangling link included.
outputFree :: FilePath -> IO (Either Text ())
outputFree path = do
    status <- try @IOException (getSymbolicLinkStatus path)
    pure $ case status of
        Left _ -> Right ()
        Right _ -> Left (renderVaultRefusal (VaultPathExists path))

-- | A file's bytes, or the line saying what could not be read.
readBytes :: Text -> FilePath -> ExceptT Text IO ByteString
readBytes what path =
    ExceptT . fmap (first (const unreadable)) $
        tryIOError (BS.readFile path)
  where
    unreadable = "cannot read the " <> what <> ": " <> T.pack path

-- * The terminal

{- | The interface on the terminal of the process: messages on standard
error, other requests on @\/dev\/tty@, which is opened for each request
and closed after it. A request that finds no terminal is refused.
-}
terminalPluginUi :: PluginUi
terminalPluginUi = pluginUiWith onTerminal stderr
  where
    onTerminal :: (Fd -> Handle -> IO a) -> IO (Maybe a)
    onTerminal use = do
        outcome <-
            try @IOException $
                bracket
                    ( do
                        fd <- openFd "/dev/tty" ReadWrite defaultFileFlags
                        handle <- fdToHandle fd
                        hSetBuffering handle NoBuffering
                        pure (fd, handle)
                    )
                    (hClose . snd)
                    (uncurry use)
        pure (either (const Nothing) Just outcome)

{- | The interface over a terminal that is already open — its descriptor
and its handle — with messages on a handle of their own.
-}
pluginUiOn :: Fd -> Handle -> Handle -> PluginUi
pluginUiOn fd terminal = pluginUiWith onTerminal
  where
    onTerminal :: (Fd -> Handle -> IO a) -> IO (Maybe a)
    onTerminal use = do
        outcome <- try @IOException (use fd terminal)
        pure (either (const Nothing) Just outcome)

{- | The interface over a way to reach the terminal and a handle for
messages. Prompts are written as bytes, so no locale can make one fail.
-}
pluginUiWith
    :: (forall a. (Fd -> Handle -> IO a) -> IO (Maybe a))
    -> Handle
    -> PluginUi
pluginUiWith onTerminal messages =
    PluginUi
        { uiMessage = \message -> do
            BS.hPut messages (TE.encodeUtf8 (visible message) <> "\n")
            hFlush messages
        , uiRequestPublic = \prompt ->
            fmap (fmap decodeLine) . onTerminal $ \_ terminal ->
                typedLine terminal False (visible prompt <> ": ")
        , uiRequestSecret = \prompt ->
            onTerminal $ \fd terminal ->
                withHiddenEcho fd $
                    typedLine terminal True (visible prompt <> ": ")
        , uiConfirm = \prompt yes no ->
            fmap join . onTerminal $ \_ terminal -> do
                typed <-
                    typedLine
                        terminal
                        False
                        (visible prompt <> " [" <> choices yes no <> "]: ")
                pure (chosen yes no (decodeLine typed))
        }
  where
    visible = T.map (\c -> if isControl c then ' ' else c)
    decodeLine = TE.decodeUtf8With lenientDecode
    choices yes = maybe (visible yes) (\n -> visible yes <> "/" <> visible n)
    chosen yes no typed
        | same typed yes = Just True
        | Just n <- no, same typed n = Just False
        | otherwise = Nothing
    same a b = T.toLower (T.strip a) == T.toLower (T.strip b)

{- | Write a prompt to the terminal and read the line typed. After a line
typed with the echo off the line break is the prompt's, never the text.
-}
typedLine :: Handle -> Bool -> Text -> IO ByteString
typedLine terminal echoOff prompt = do
    BS.hPut terminal (TE.encodeUtf8 prompt)
    hFlush terminal
    typed <- BC.hGetLine terminal
    when echoOff $ BS.hPut terminal "\n" >> hFlush terminal
    pure (BC.dropWhileEnd (\c -> c == '\r' || c == '\n') typed)
