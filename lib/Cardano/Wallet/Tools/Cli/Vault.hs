{- |
Module      : Cardano.Wallet.Tools.Cli.Vault
Description : The vault commands of cwt: option parsers and handlers
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The command-line surface of the vault: where a signing key comes from
for @cwt sign@, and the handler behind @cwt vault seal@. The passphrase
comes from the terminal or from an inherited descriptor
(@--passphrase-fd N@) and from nowhere else.
-}
module Cardano.Wallet.Tools.Cli.Vault
    ( -- * Signing key source
      SigningKeySource (..)
    , signingKeySourceParser
    , loadSignerFromSource

      -- * Sealing
    , VaultSealOptions (..)
    , vaultSealParser
    , runVaultSeal
    ) where

import Cardano.Wallet.Tools.Sign (Signer)
import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , createVaultFile
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase
    ( Confirmation (..)
    , PassphraseSource (..)
    , readPassphrase
    , renderPassphraseRefusal
    )
import Cardano.Wallet.Tools.Vault.Payload
    ( IdentitySelector (..)
    , OpenedKey (..)
    , parseSigningKeyEnvelope
    , signerFromKey
    )
import Cardano.Wallet.Tools.Vault.Scrypt
    ( openVault
    , sealVault
    , vaultWorkFactorCap
    )
import Control.Monad.Trans.Except (ExceptT (..), except, runExceptT)
import Crypto.Age.Scrypt
    ( WorkFactor (..)
    , mkWorkFactor
    )
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text (Text)
import Data.Text qualified as T
import Foreign.C.Types (CInt)
import Options.Applicative
import System.IO.Error (tryIOError)
import Text.Read (readMaybe)

-- | Where @cwt sign@ takes its signing key from.
data SigningKeySource
    = -- | a plaintext @cardano-cli@ signing-key envelope file
      PlaintextKey FilePath
    | -- | a vault file, its passphrase source, an optional identity
      VaultKey FilePath PassphraseSource (Maybe IdentitySelector)
    deriving stock (Eq, Show)

-- | What @cwt vault seal@ was asked to do.
data VaultSealOptions = VaultSealOptions
    { sealKeyPath :: FilePath
    -- ^ the plaintext signing key to seal
    , sealOutPath :: FilePath
    -- ^ the vault file to create, which must not exist
    , sealPassphrase :: PassphraseSource
    -- ^ where the passphrase comes from
    , sealWorkFactor :: WorkFactor
    -- ^ the scrypt work factor recorded in the vault
    }
    deriving stock (Eq, Show)

{- | @--signing-key FILE@, or @--signing-key-vault FILE@ with an optional
@--passphrase-fd N@ and @--vault-identity LABEL@.
-}
signingKeySourceParser :: Parser SigningKeySource
signingKeySourceParser = vaultKey <|> plaintextKey
  where
    plaintextKey =
        PlaintextKey
            <$> strOption
                ( long "signing-key"
                    <> metavar "FILE"
                    <> help
                        "Path to a plaintext cardano-cli signing key text envelope"
                )
    vaultKey =
        VaultKey
            <$> strOption
                ( long "signing-key-vault"
                    <> metavar "FILE"
                    <> help "Path to an age signing key vault"
                )
            <*> passphraseSourceParser
            <*> optional
                ( IdentitySelector . T.pack
                    <$> strOption
                        ( long "vault-identity"
                            <> metavar "LABEL"
                            <> help
                                "Identity to sign with, in a vault holding several"
                        )
                )

-- | @--signing-key FILE --out FILE@ with the passphrase and work factor flags.
vaultSealParser :: Parser VaultSealOptions
vaultSealParser =
    VaultSealOptions
        <$> strOption
            ( long "signing-key"
                <> metavar "FILE"
                <> help "Plaintext cardano-cli signing key to seal"
            )
        <*> strOption
            ( long "out"
                <> metavar "FILE"
                <> help "Vault file to create; it must not exist"
            )
        <*> passphraseSourceParser
        <*> option
            workFactorReader
            ( long "work-factor"
                <> metavar "N"
                <> value vaultWorkFactorCap
                <> showDefaultWith (\(WorkFactor n) -> show n)
                <> help "Scrypt work factor, 1 to the cap"
            )

-- | The terminal unless a descriptor is named.
passphraseSourceParser :: Parser PassphraseSource
passphraseSourceParser =
    maybe PassphraseTerminal PassphraseDescriptor
        <$> optional
            ( option
                descriptorReader
                ( long "passphrase-fd"
                    <> metavar "N"
                    <> help
                        "Read the passphrase from the inherited descriptor N (default: ask on /dev/tty)"
                )
            )

descriptorReader :: ReadM Int
descriptorReader = eitherReader $ \raw ->
    case readMaybe raw of
        Just n
            | n >= 0 && n <= fromIntegral (maxBound :: CInt) -> Right n
        _ -> Left "expected a descriptor number"

workFactorReader :: ReadM WorkFactor
workFactorReader = eitherReader $ \raw ->
    case readMaybe raw of
        Just n
            | n >= 1
            , n <= capNumber
            , Just factor <- mkWorkFactor (fromIntegral n) ->
                Right factor
        _ ->
            Left ("expected a work factor from 1 to " <> show capNumber)

-- | The cap as a number: the parser's upper bound and its message.
capNumber :: Int
capNumber = let WorkFactor cap = vaultWorkFactorCap in fromIntegral cap

{- | Seal the key file into a new vault file; the refusal, rendered, on
failure. The key is read and checked, and the passphrase asked twice on a
terminal, before the vault file is created.
-}
runVaultSeal :: VaultSealOptions -> IO (Either Text ())
runVaultSeal options = runExceptT $ do
    keyFile <- readBytes "signing key file" (sealKeyPath options)
    key <-
        except . first (const notAKey) $
            parseSigningKeyEnvelope keyFile
    passphrase <-
        ExceptT . fmap (first renderPassphraseRefusal) $
            readPassphrase AskTwice (sealPassphrase options)
    vault <-
        ExceptT . fmap (first (const notWritten)) $
            sealVault (sealWorkFactor options) passphrase key
    ExceptT . fmap (first renderVaultRefusal) $
        createVaultFile (sealOutPath options) vault
  where
    notAKey =
        "seal input is not a signing key: " <> T.pack (sealKeyPath options)
    notWritten = renderVaultRefusal (VaultNotWritten (sealOutPath options))

-- | The signer for the source; the refusal, rendered, on failure.
loadSignerFromSource
    :: SigningKeySource -> IO (Either Text (Signer IO))
loadSignerFromSource = \case
    PlaintextKey path -> runExceptT $ do
        keyFile <- readBytes "signing key file" path
        key <-
            except . first (const (notAKey path)) $
                parseSigningKeyEnvelope keyFile
        pure (signerFromKey (OpenedPlain key))
    VaultKey path source selector -> runExceptT $ do
        vault <- readBytes "vault file" path
        passphrase <-
            ExceptT . fmap (first renderPassphraseRefusal) $
                readPassphrase AskOnce source
        key <-
            except . first renderVaultRefusal $
                openVault selector passphrase vault
        pure (signerFromKey key)
  where
    notAKey path = "not a payment signing key: " <> T.pack path

-- | A file's bytes, or the line saying what could not be read.
readBytes :: Text -> FilePath -> ExceptT Text IO ByteString
readBytes what path =
    ExceptT . fmap (first (const unreadable)) $
        tryIOError (BS.readFile path)
  where
    unreadable = "cannot read the " <> what <> ": " <> T.pack path
