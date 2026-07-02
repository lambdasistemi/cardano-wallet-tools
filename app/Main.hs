{- HLINT ignore "Use newtype instead of data" -}
module Main where

import Cardano.Wallet.Tools.Cli.Vault
import Cardano.Wallet.Tools.Sign
import Cardano.Wallet.Tools.Vault
import Cli.Key (die)
import Cli.Pipe (readCborHex, writeCborHex)
import Control.Monad (when)
import Data.ByteString qualified as BS
import Data.Text qualified as T
import Options.Applicative

data Command
    = Sign SigningKeySource
    | VaultSeal FilePath FilePath

parseSign :: Parser Command
parseSign = Sign <$> signingKeySourceParser

parseVaultSeal :: Parser Command
parseVaultSeal =
    VaultSeal
        <$> strOption
            ( long "signing-key"
                <> metavar "FILE"
                <> help "Plaintext .skey TextEnvelope to encrypt"
            )
        <*> strOption
            ( long "out"
                <> metavar "FILE"
                <> help "Output .age vault file"
            )

parseVault :: Parser Command
parseVault =
    hsubparser
        ( command
            "seal"
            ( info
                parseVaultSeal
                (progDesc "Encrypt a signing key into an age scrypt vault")
            )
        )

parseCommand :: Parser Command
parseCommand =
    hsubparser
        ( command
            "sign"
            ( info
                parseSign
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
            signer <- loadSignerFromSource keySrc
            txBytes <- readCborHex
            body <-
                either (die . ("cannot extract tx body: " <>) . show) pure $
                    transactionBodyBytes txBytes
            witness <- signTxBody signer body
            signedTx <-
                either (die . ("cannot attach witness: " <>) . show) pure $
                    attachWitnesses [witness] txBytes
            writeCborHex signedTx
        VaultSeal keyPath outPath -> do
            keyBytes <- BS.readFile keyPath
            pp1 <- promptPassphrase "vault passphrase: "
            pp2 <- promptPassphrase "confirm passphrase: "
            when (pp1 /= pp2) $ die "passphrases do not match"
            vaultPass <-
                either (die . T.unpack . renderVaultError) pure $
                    mkVaultPassphrase pp1
            cipher <-
                encryptVault defaultWorkFactor vaultPass keyBytes
                    >>= either (die . T.unpack . renderVaultError) pure
            BS.writeFile outPath cipher
