module Main where

import Cardano.Wallet.Tools.Cli.Vault
import Cardano.Wallet.Tools.Sign
import Cli.Key (die)
import Cli.Pipe (readCborHex, writeCborHex)
import Data.Text qualified as T
import Options.Applicative

data Command
    = Sign SigningKeySource
    | VaultSeal VaultSealOptions

parseVault :: Parser Command
parseVault =
    hsubparser
        ( command
            "seal"
            ( info
                (VaultSeal <$> vaultSealParser)
                (progDesc "Encrypt a signing key into an age scrypt vault")
            )
        )

parseCommand :: Parser Command
parseCommand =
    hsubparser
        ( command
            "sign"
            ( info
                (Sign <$> signingKeySourceParser)
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
        )

opts :: ParserInfo Command
opts =
    info
        (parseCommand <**> helper)
        ( fullDesc
            <> progDesc "Cardano wallet-side operator toolkit"
            <> header "cwt - cardano-wallet-tools CLI"
        )

main :: IO ()
main = do
    cmd <- execParser opts
    case cmd of
        Sign keySrc -> do
            signer <-
                loadSignerFromSource keySrc
                    >>= either (die . T.unpack) pure
            txBytes <- readCborHex
            body <-
                either (die . ("cannot extract tx body: " <>) . show) pure $
                    transactionBodyBytes txBytes
            witness <- signTxBody signer body
            signedTx <-
                either (die . ("cannot attach witness: " <>) . show) pure $
                    attachWitnesses [witness] txBytes
            writeCborHex signedTx
        VaultSeal options ->
            runVaultSeal options >>= either (die . T.unpack) pure
