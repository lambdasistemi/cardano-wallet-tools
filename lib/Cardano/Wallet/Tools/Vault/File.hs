{- |
Module      : Cardano.Wallet.Tools.Vault.File
Description : Creating a vault file exclusively, mode 0600
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The vault file is owned by the command that creates it, for the length
of that command: it is created exclusively with mode 0600 (an existing
path, including a symbolic link, is refused and left untouched), and a
write that fails after the file was made removes that file.
-}
module Cardano.Wallet.Tools.Vault.File
    ( -- * Creation
      withVaultFile
    , createVaultFile

      -- * Refusals
    , VaultRefusal (..)
    , renderVaultRefusal
    ) where

import Cardano.Wallet.Tools.Vault.Payload
    ( VaultPayloadRefusal
    , renderVaultPayloadRefusal
    )
import Control.Exception
    ( IOException
    , SomeException
    , fromException
    , mask
    , onException
    , throwIO
    , try
    )
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text (Text)
import Data.Text qualified as T
import System.IO (Handle, hClose)
import System.IO.Error (isAlreadyExistsError)
import System.Posix.Files
    ( FileStatus
    , deviceID
    , fileID
    , getFdStatus
    , getSymbolicLinkStatus
    , ownerReadMode
    , ownerWriteMode
    , removeLink
    , unionFileModes
    )
import System.Posix.IO
    ( OpenFileFlags (..)
    , OpenMode (WriteOnly)
    , closeFd
    , defaultFileFlags
    , fdToHandle
    , openFd
    )
import System.Posix.Types (FileMode)

{- | Why a vault operation was refused. None names the passphrase or the
key; 'VaultNotOpened' is the one opening refusal for every way a vault
fails to open.
-}
data VaultRefusal
    = -- | the vault path already exists, naming it; it is untouched
      VaultPathExists FilePath
    | -- | the file could not be created or written, naming the path
      VaultNotWritten FilePath
    | -- | wrong passphrase, corrupt file, not a vault, or not a key
      VaultNotOpened
    | -- | the vault opened, but not to the requested identity
      VaultPayloadRefused VaultPayloadRefusal
    deriving stock (Eq, Show)

{- | Create the file exclusively with mode 0600, hand the writer its
handle, and remove the file this call made if the writer fails.

The file and its descriptor are owned from the moment they exist: the
whole interval from creation to the writer's first byte, and from the
writer's last byte to the return, runs with asynchronous exceptions
masked, so an interruption can only arrive inside the writer, and there
it removes the file like any other failure.
-}
withVaultFile
    :: FilePath
    -> (Handle -> IO a)
    -> IO (Either VaultRefusal a)
withVaultFile path write = mask $ \restore -> do
    created <- create
    case created of
        Left refusal -> pure (Left refusal)
        Right (fd, made) -> do
            handle <-
                fdToHandle fd
                    `onException` (closeQuietly fd >> removeIfStillMade made)
            written <- try $ do
                result <- restore (write handle)
                hClose handle
                pure result
            case written of
                Right result -> pure (Right result)
                Left e -> do
                    void (try @IOException (hClose handle))
                    removeIfStillMade made
                    case fromException e of
                        Just (_ :: IOException) ->
                            pure (Left (VaultNotWritten path))
                        Nothing -> throwIO (e :: SomeException)
  where
    create = do
        opened <-
            try $
                openFd
                    path
                    WriteOnly
                    defaultFileFlags
                        { exclusive = True
                        , creat = Just vaultFileMode
                        , nofollow = True
                        }
        case opened of
            Left e
                | isAlreadyExistsError e ->
                    pure (Left (VaultPathExists path))
                | otherwise -> pure (Left (VaultNotWritten path))
            Right fd -> do
                status <- try (getFdStatus fd)
                case status of
                    Right made -> pure (Right (fd, made))
                    Left (_ :: IOException) -> do
                        closeQuietly fd
                        void (try @IOException (removeLink path))
                        pure (Left (VaultNotWritten path))

    closeQuietly fd = void (try @IOException (closeFd fd))

    -- the path is removed only while it still names the file this call
    -- made, so a failed write cannot delete a file put there since
    removeIfStillMade :: FileStatus -> IO ()
    removeIfStillMade made = do
        now <- try (getSymbolicLinkStatus path)
        case now of
            Right status
                | deviceID status == deviceID made
                    && fileID status == fileID made ->
                    void (try @IOException (removeLink path))
            Right _ -> pure ()
            Left (_ :: IOException) -> pure ()

-- | Create the vault file exclusively and write the bytes.
createVaultFile
    :: FilePath -> ByteString -> IO (Either VaultRefusal ())
createVaultFile path bytes = withVaultFile path (`BS.hPut` bytes)

-- | The mode a vault is born with: its owner reads and writes, no one else.
vaultFileMode :: FileMode
vaultFileMode = ownerReadMode `unionFileModes` ownerWriteMode

-- | One line naming the refusal, carrying no secret.
renderVaultRefusal :: VaultRefusal -> Text
renderVaultRefusal = \case
    VaultPathExists path -> "vault already exists: " <> T.pack path
    VaultNotWritten path -> "cannot write the vault file: " <> T.pack path
    VaultNotOpened ->
        "cannot open vault: wrong passphrase, corrupt file, or not a vault"
    VaultPayloadRefused refusal -> renderVaultPayloadRefusal refusal
