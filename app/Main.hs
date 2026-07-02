{- HLINT ignore "Use newtype instead of data" -}
module Main where

import Cardano.Wallet.Tools.Sign
import Cli.Key (die, loadSigner)
import Cli.Pipe (readCborHex, writeCborHex)
import Options.Applicative

data Command
    = Sign FilePath

parseSign :: Parser Command
parseSign =
    Sign
        <$> strOption
            ( long "signing-key"
                <> metavar "FILE"
                <> help "Path to a cardano-cli TextEnvelope ed25519 signing key"
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
        Sign keyPath -> do
            signer <- loadSigner keyPath
            txBytes <- readCborHex
            body <-
                either (die . ("cannot extract tx body: " <>) . show) pure $
                    transactionBodyBytes txBytes
            witness <- signTxBody signer body
            signedTx <-
                either (die . ("cannot attach witness: " <>) . show) pure $
                    attachWitnesses [witness] txBytes
            writeCborHex signedTx
