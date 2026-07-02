module Cli.Key where

import Cardano.Wallet.Tools.Sign
import Control.Monad (unless)
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Data.Aeson (FromJSON (..), withObject, (.:))
import Data.Aeson qualified as Aeson
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

data TextEnvelope = TextEnvelope
    { teType :: !Text
    , teCborHex :: !Text
    }

instance FromJSON TextEnvelope where
    parseJSON = withObject "TextEnvelope" $ \o ->
        TextEnvelope <$> o .: "type" <*> o .: "cborHex"

paymentKeyTypes :: [Text]
paymentKeyTypes =
    [ "PaymentSigningKeyShelley_ed25519"
    , "PaymentExtendedSigningKeyShelley_ed25519_bip32"
    , "GenesisUTxOSigningKey_ed25519"
    ]

die :: String -> IO a
die msg = hPutStrLn stderr ("cwt: " <> msg) >> exitFailure

loadSigner :: FilePath -> IO (Signer IO)
loadSigner path = do
    mEnv <- Aeson.decodeFileStrict' path
    env <- maybe (die $ "cannot parse TextEnvelope: " <> path) pure mEnv
    unless (teType env `elem` paymentKeyTypes) $
        die $
            "unsupported key type: " <> T.unpack (teType env)
    hexBytes <-
        either (die . (("invalid cborHex in " <> path <> ": ") <>)) pure
            . B16.decode
            . TE.encodeUtf8
            . teCborHex
            $ env
    rawKey <- stripCborByteStringHeader path hexBytes
    sk <- case Ed25519.secretKey (rawKey :: ByteString) of
        CryptoPassed k -> pure k
        CryptoFailed e -> die $ "invalid ed25519 key in " <> path <> ": " <> show e
    let pk = Ed25519.toPublic sk
    let vkeyBytes = BA.convert pk :: ByteString
    pure . Signer $ \(TxBodyBytes body) -> do
        let sig = Ed25519.sign sk pk body
        let sigBytes = BA.convert sig :: ByteString
        pure $ DetachedWitness vkeyBytes sigBytes

stripCborByteStringHeader :: FilePath -> ByteString -> IO ByteString
stripCborByteStringHeader path bs = case BS.uncons bs of
    Just (0x58, rest) ->
        case BS.uncons rest of
            Just (len, keyBytes)
                | fromIntegral len == BS.length keyBytes && len == 32 ->
                    pure keyBytes
            _ -> die $ "unexpected key length in " <> path
    Just (0x20, _) -> die $ "cborHex looks like a public key in " <> path
    _ -> die $ "unexpected CBOR header in " <> path
