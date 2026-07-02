module Cli.Key where

import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

die :: String -> IO a
die msg = hPutStrLn stderr ("cwt: " <> msg) >> exitFailure
