module Main where

import Cardano.Wallet.Tools.Cli.Fido2
import Cardano.Wallet.Tools.Cli.Vault
import Cardano.Wallet.Tools.Ledger.Cli.Bundle
import Cardano.Wallet.Tools.Sign
import Cli.Key (die)
import Cli.Pipe (readCborHex, writeCborHex)
import Data.Text qualified as T
import Options.Applicative
import System.Exit (exitFailure)
import System.IO (hPutStr, stderr)

data Command
    = Sign SigningKeySource
    | SignFido2 Fido2KeySource
    | VaultSeal VaultSealOptions
    | BundleCheck BundleCheckOptions
    | VaultCreate VaultCreateOptions
    | VaultRekey VaultRekeyOptions

parseVault :: Parser Command
parseVault =
    hsubparser
        ( command
            "seal"
            ( info
                (VaultSeal <$> vaultSealParser)
                (progDesc "Encrypt a signing key into an age scrypt vault")
            )
            <> command
                "create"
                ( info
                    (VaultCreate <$> vaultCreateParser)
                    ( progDesc
                        "Encrypt a signing key into a vault only FIDO2 authenticators open"
                    )
                )
            <> command
                "rekey"
                ( info
                    (VaultRekey <$> vaultRekeyParser)
                    ( progDesc
                        "Write the key of a FIDO2 vault to a new set of authenticators"
                    )
                )
        )

parseBundle :: Parser Command
parseBundle =
    hsubparser
        ( command
            "check"
            ( info
                (BundleCheck <$> bundleCheckParser)
                (progDesc "Run the offline checks of a bundle v1 file")
            )
        )

parseCommand :: Parser Command
parseCommand =
    hsubparser
        ( command
            "sign"
            ( info
                ( (Sign <$> signingKeySourceParser)
                    <|> (SignFido2 <$> fido2KeySourceParser)
                )
                ( progDesc
                    "Attach a vkey witness to a tx body (CBOR hex stdin → stdout)"
                )
            )
            <> command
                "vault"
                ( info
                    parseVault
                    (progDesc "Manage age-encrypted signing key vaults")
                )
            <> command
                "bundle"
                ( info
                    parseBundle
                    (progDesc "Inspect bundles of unsigned transactions")
                )
        )

opts :: ParserInfo Command
opts =
    info
        (parseCommand <**> helper)
        ( fullDesc
            <> progDesc "Cardano wallet-side operator toolkit"
            <> header "cwt - cardano-wallet-tools CLI"
        )

-- | Sign the transaction on standard input and write it back signed.
signStdin :: Signer IO -> IO ()
signStdin signer = do
    txBytes <- readCborHex
    body <-
        either (die . ("cannot extract tx body: " <>) . show) pure $
            transactionBodyBytes txBytes
    witness <- signTxBody signer body
    signedTx <-
        either (die . ("cannot attach witness: " <>) . show) pure $
            attachWitnesses [witness] txBytes
    writeCborHex signedTx

main :: IO ()
main = do
    cmd <- execParser opts
    case cmd of
        Sign keySrc ->
            loadSignerFromSource keySrc
                >>= either (die . T.unpack) pure
                >>= signStdin
        SignFido2 source ->
            loadSignerFromFido2 terminalPluginUi source
                >>= either (die . T.unpack) pure
                >>= signStdin
        VaultSeal options ->
            runVaultSeal options >>= either (die . T.unpack) pure
        BundleCheck options ->
            runBundleCheck options >>= \case
                Right summary -> putStrLn summary
                Left failures -> hPutStr stderr (unlines failures) >> exitFailure
        VaultCreate options ->
            runVaultCreate terminalPluginUi options
                >>= either (die . T.unpack) pure
        VaultRekey options ->
            runVaultRekey terminalPluginUi options
                >>= either (die . T.unpack) pure
