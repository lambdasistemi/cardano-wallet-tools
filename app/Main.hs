{- HLINT ignore "Use newtype instead of data" -}
module Main where

import Options.Applicative
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

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
        Sign _ -> do
            hPutStrLn
                stderr
                "cwt sign: not yet implemented (coming in next release)"
            exitFailure
