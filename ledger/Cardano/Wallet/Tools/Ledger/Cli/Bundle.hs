{- |
Module      : Cardano.Wallet.Tools.Ledger.Cli.Bundle
Description : The @cwt bundle check@ command: option parser and runner
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

@cwt bundle check FILE@ reads one bundle v1 file and runs the offline
checks, with no network. The runner returns the summary when every
check passes, and otherwise one line per failed check; @cwt@ maps the
second to a non-zero exit.
-}
module Cardano.Wallet.Tools.Ledger.Cli.Bundle
    ( BundleCheckOptions (..)
    , bundleCheckParser
    , runBundleCheck
    ) where

import Cardano.Wallet.Tools.Ledger.Bundle
    ( Bundle (..)
    , bundleRefusals
    , decodeBundle
    , renderBundleRefusal
    )
import Data.ByteString qualified as BS
import Options.Applicative
    ( Parser
    , help
    , metavar
    , strArgument
    )
import System.IO.Error (ioeGetErrorString, tryIOError)

-- | What @cwt bundle check@ was asked to do.
newtype BundleCheckOptions = BundleCheckOptions
    { bundleCheckFile :: FilePath
    -- ^ the bundle file to check
    }
    deriving stock (Eq, Show)

-- | The positional @FILE@ argument.
bundleCheckParser :: Parser BundleCheckOptions
bundleCheckParser =
    BundleCheckOptions
        <$> strArgument
            ( metavar "FILE"
                <> help "Path to a bundle v1 JSON file"
            )

{- | Read the file and run the offline checks: the summary when they all
pass, otherwise one line per failed check, or the reason the file could
not be read or decoded.
-}
runBundleCheck :: BundleCheckOptions -> IO (Either [String] String)
runBundleCheck (BundleCheckOptions path) = do
    contents <- tryIOError (BS.readFile path)
    pure $ case contents of
        Left failure ->
            Left
                [ "cannot read "
                    <> show path
                    <> ": "
                    <> ioeGetErrorString failure
                ]
        Right bytes -> case decodeBundle bytes of
            Left refusal -> Left [renderBundleRefusal refusal]
            Right bundle -> case bundleRefusals bundle of
                [] -> Right (summary bundle)
                refusals -> Left (map renderBundleRefusal refusals)

-- | The summary line of a bundle whose checks all pass.
summary :: Bundle -> String
summary bundle =
    "ok: transactions="
        <> show (length (bundleTransactions bundle))
        <> " signers="
        <> show (length (bundleSigners bundle))
        <> " networkMagic="
        <> show (bundleNetworkMagic bundle)
