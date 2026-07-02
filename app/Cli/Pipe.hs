module Cli.Pipe where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

readCborHex :: IO ByteString
readCborHex = do
    hex <- BS.getContents
    let stripped = BS.dropWhileEnd (\c -> c == 10 || c == 13 || c == 32) hex
    case B16.decode stripped of
        Left err -> do
            hPutStrLn stderr $ "cwt: invalid CBOR hex: " <> err
            exitFailure
        Right bytes -> pure bytes

writeCborHex :: ByteString -> IO ()
writeCborHex = BS.putStr . B16.encode
