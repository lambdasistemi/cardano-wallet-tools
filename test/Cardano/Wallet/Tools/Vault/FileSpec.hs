{- |
Module      : Cardano.Wallet.Tools.Vault.FileSpec
Description : The vault file is created exclusively, mode 0600
License     : Apache-2.0

The file proofs of the vault: it is born readable by its owner only, an
existing path or symbolic link is refused with its bytes and target
untouched, and a write that fails removes the file the call made.
-}
module Cardano.Wallet.Tools.Vault.FileSpec (spec) where

import Cardano.Wallet.Tools.Vault.File
import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (ErrorCall (..), bracket, finally, mask)
import Control.Monad (forM_, forever)
import Data.Bits ((.&.))
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Text qualified as T
import Support.Vault (withTempDir)
import System.Directory
    ( doesPathExist
    , listDirectory
    , removeFile
    , renameFile
    )
import System.FilePath ((</>))
import System.Posix.Files
    ( createSymbolicLink
    , fileMode
    , fileSize
    , getFileStatus
    , getSymbolicLinkStatus
    , isSymbolicLink
    , setFileCreationMask
    )
import Test.Hspec

spec :: Spec
spec = describe "vault v1" $
    describe "exclusive creation" $ do
        let vaultBytes = BC.pack "the sealed vault bytes"

        it "creates the file readable by its owner only, holding the bytes" $
            withTempDir "vault-create" $ \dir -> do
                let path = dir </> "alice.vault"
                createVaultFile path vaultBytes `shouldReturn` Right ()
                BS.readFile path `shouldReturn` vaultBytes
                mode <- fileMode <$> getFileStatus path
                (mode .&. 0o777) `shouldBe` 0o600

        it "creates mode 0600 whatever the process umask allows" $
            withTempDir "vault-umask" $ \dir -> do
                let path = dir </> "alice.vault"
                bracket (setFileCreationMask 0o000) setFileCreationMask $
                    \_ -> createVaultFile path vaultBytes `shouldReturn` Right ()
                mode <- fileMode <$> getFileStatus path
                (mode .&. 0o777) `shouldBe` 0o600

        it "has the file at mode 0600 and empty before the first byte" $
            withTempDir "vault-born" $ \dir -> do
                let path = dir </> "alice.vault"
                outcome <- withVaultFile path $ \_ -> do
                    status <- getFileStatus path
                    pure (fileMode status .&. 0o777, fileSize status)
                outcome `shouldBe` Right (0o600, 0)

        it "refuses an existing path and leaves its bytes unchanged" $
            withTempDir "vault-exists" $ \dir -> do
                let path = dir </> "alice.vault"
                    original = BC.pack "the wallet that lives here already"
                BS.writeFile path original
                createVaultFile path vaultBytes
                    `shouldReturn` Left (VaultPathExists path)
                BS.readFile path `shouldReturn` original

        it "refuses a symbolic link and leaves its target untouched" $
            withTempDir "vault-symlink" $ \dir -> do
                let target = dir </> "real.vault"
                    link = dir </> "alice.vault"
                    original = BC.pack "the symlinked wallet"
                BS.writeFile target original
                createSymbolicLink "real.vault" link
                createVaultFile link vaultBytes
                    `shouldReturn` Left (VaultPathExists link)
                BS.readFile target `shouldReturn` original
                isSymbolicLink <$> getSymbolicLinkStatus link
                    `shouldReturn` True

        it "does not follow a dangling symbolic link to create its target" $
            withTempDir "vault-dangling" $ \dir -> do
                let target = dir </> "nowhere.vault"
                    link = dir </> "alice.vault"
                createSymbolicLink "nowhere.vault" link
                createVaultFile link vaultBytes
                    `shouldReturn` Left (VaultPathExists link)
                doesPathExist target `shouldReturn` False

        it "removes the file it made when the write fails" $
            withTempDir "vault-failed-write" $ \dir -> do
                let path = dir </> "alice.vault"
                withVaultFile
                    path
                    (\_ -> ioError (userError "the write fails") :: IO ())
                    `shouldReturn` Left (VaultNotWritten path)
                doesPathExist path `shouldReturn` False

        it "removes only the file it made when the write fails" $
            withTempDir "vault-only-its-own" $ \dir -> do
                let path = dir </> "alice.vault"
                    neighbour = dir </> "bob.vault"
                BS.writeFile neighbour vaultBytes
                _ <-
                    withVaultFile
                        path
                        (\_ -> ioError (userError "the write fails") :: IO ())
                listDirectory dir `shouldReturn` ["bob.vault"]
                BS.readFile neighbour `shouldReturn` vaultBytes

        it "does not remove a file that replaced it while the write ran" $
            withTempDir "vault-replaced" $ \dir -> do
                let path = dir </> "alice.vault"
                    other = dir </> "other.vault"
                BS.writeFile other "someone else's file"
                _ <- withVaultFile path $ \_ -> do
                    renameFile other path
                    ioError (userError "the write fails") :: IO ()
                BS.readFile path `shouldReturn` "someone else's file"

        it "removes the file and rethrows when the writer throws otherwise" $
            withTempDir "vault-thrown" $ \dir -> do
                let path = dir </> "alice.vault"
                withVaultFile path (\_ -> error "writer broke" :: IO ())
                    `shouldThrow` (\(ErrorCall m) -> m == "writer broke")
                doesPathExist path `shouldReturn` False

        it "leaves no file when it is interrupted at any point" $
            withTempDir "vault-interrupted" $ \dir -> do
                let path = dir </> "alice.vault"
                forM_ [1 .. 120 :: Int] $ \trial -> do
                    finished <- newEmptyMVar
                    victim <-
                        forkIO $
                            mask
                                ( \restore -> forever $ do
                                    outcome <-
                                        restore $
                                            withVaultFile path (`BS.hPut` vaultBytes)
                                    either (const (pure ())) (const (removeFile path)) outcome
                                )
                                `finally` putMVar finished ()
                    threadDelay (1000 * (1 + trial `mod` 7))
                    killThread victim
                    takeMVar finished
                    listDirectory dir `shouldReturn` []

        it "keeps the file when the write succeeds" $
            withTempDir "vault-written" $ \dir -> do
                let path = dir </> "alice.vault"
                withVaultFile path (`BS.hPut` vaultBytes)
                    `shouldReturn` Right ()
                BS.readFile path `shouldReturn` vaultBytes

        it "refuses a path whose directory does not exist, creating nothing" $
            withTempDir "vault-no-dir" $ \dir -> do
                let path = dir </> "missing" </> "alice.vault"
                createVaultFile path vaultBytes
                    `shouldReturn` Left (VaultNotWritten path)
                listDirectory dir `shouldReturn` []

        it "names the path in the refusal and nothing secret" $ do
            let path = "/some/where/alice.vault"
            renderVaultRefusal (VaultPathExists path)
                `shouldSatisfy` T.isInfixOf (T.pack path)
            renderVaultRefusal (VaultNotWritten path)
                `shouldSatisfy` T.isInfixOf (T.pack path)
