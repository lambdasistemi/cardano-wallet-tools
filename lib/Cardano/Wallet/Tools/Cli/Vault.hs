module Cardano.Wallet.Tools.Cli.Vault
    ( -- * Signing key source (reusable parser surface)
      SigningKeySource (..)
    , PassphraseSource (..)
    , signingKeySourceParser

      -- * Passphrase I/O
    , promptPassphrase
    , readPassphrase

      -- * Signer construction
    , loadSignerFromSource
    , loadSignerFromFile
    ) where

import Cardano.Wallet.Tools.Sign
import Cardano.Wallet.Tools.Vault
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
import Options.Applicative
import System.Exit (exitFailure)
import System.IO

-- ---------------------------------------------------------------------------
-- CLI option types

data SigningKeySource
    = PlaintextKey FilePath
    | VaultKey FilePath PassphraseSource

data PassphraseSource
    = InteractivePassphrase
    | PassphraseFile FilePath

signingKeySourceParser :: Parser SigningKeySource
signingKeySourceParser = vaultKey <|> plaintextKey
  where
    plaintextKey =
        PlaintextKey
            <$> strOption
                ( long "signing-key"
                    <> metavar "FILE"
                    <> help
                        "Path to a plaintext cardano-cli TextEnvelope ed25519 signing key"
                )
    vaultKey =
        VaultKey
            <$> strOption
                ( long "signing-key-vault"
                    <> metavar "FILE"
                    <> help "Path to an age-encrypted signing key vault (.age)"
                )
            <*> passphraseSourceParser

passphraseSourceParser :: Parser PassphraseSource
passphraseSourceParser =
    maybe InteractivePassphrase PassphraseFile
        <$> optional
            ( strOption
                ( long "passphrase-file"
                    <> metavar "FILE"
                    <> help
                        "Read vault passphrase from FILE (default: prompt on /dev/tty)"
                )
            )

-- ---------------------------------------------------------------------------
-- Passphrase I/O

{- | Prompt for a passphrase on /dev/tty with echo disabled. Stdin is
untouched, so this is safe to call while stdin carries a CBOR hex pipe.
-}
promptPassphrase :: String -> IO ByteString
promptPassphrase prompt = do
    tty <- openFile "/dev/tty" ReadWriteMode
    hPutStr tty prompt
    hFlush tty
    hSetEcho tty False
    line <- hGetLine tty
    hSetEcho tty True
    hPutStrLn tty ""
    hClose tty
    pure $ TE.encodeUtf8 (T.pack line)

readPassphrase :: PassphraseSource -> IO ByteString
readPassphrase = \case
    InteractivePassphrase -> promptPassphrase "vault passphrase: "
    PassphraseFile path ->
        BS.dropWhileEnd (\c -> c == 10 || c == 13 || c == 32)
            <$> BS.readFile path

-- ---------------------------------------------------------------------------
-- Signer construction

loadSignerFromSource :: SigningKeySource -> IO (Signer IO)
loadSignerFromSource = \case
    PlaintextKey path -> loadSignerFromFile path
    VaultKey path ppSrc -> do
        ciphertext <- BS.readFile path
        pp <- readPassphrase ppSrc
        vaultPass <-
            either (die . T.unpack . renderVaultError) pure $
                mkVaultPassphrase pp
        plaintext <-
            either (die . T.unpack . renderVaultError) pure $
                decryptVault vaultPass ciphertext
        parseTextEnvelopeBytes plaintext

loadSignerFromFile :: FilePath -> IO (Signer IO)
loadSignerFromFile path = BS.readFile path >>= parseTextEnvelopeBytes

-- ---------------------------------------------------------------------------
-- Internal: TextEnvelope → Signer

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

parseTextEnvelopeBytes :: ByteString -> IO (Signer IO)
parseTextEnvelopeBytes jsonBytes = do
    env <-
        maybe (die "cannot parse TextEnvelope JSON") pure $
            Aeson.decodeStrict' jsonBytes
    unless (teType env `elem` paymentKeyTypes) $
        die $
            "unsupported key type: " <> T.unpack (teType env)
    hexBytes <-
        either (die . ("invalid cborHex: " <>)) pure $
            B16.decode $
                TE.encodeUtf8 $
                    teCborHex env
    rawKey <- stripCborByteStringHeader hexBytes
    sk <- case Ed25519.secretKey (rawKey :: ByteString) of
        CryptoPassed k -> pure k
        CryptoFailed e -> die $ "invalid ed25519 key: " <> show e
    let pk = Ed25519.toPublic sk
        vkeyBytes = BA.convert pk :: ByteString
    pure . Signer $ \(TxBodyBytes body) -> do
        let sig = Ed25519.sign sk pk body
        pure $ DetachedWitness vkeyBytes (BA.convert sig :: ByteString)

stripCborByteStringHeader :: ByteString -> IO ByteString
stripCborByteStringHeader bs = case BS.uncons bs of
    Just (0x58, rest) ->
        case BS.uncons rest of
            Just (len, keyBytes)
                | fromIntegral len == BS.length keyBytes && len == 32 ->
                    pure keyBytes
            _ -> die "unexpected CBOR key length in TextEnvelope"
    Just (0x20, _) -> die "cborHex looks like a public key, not a signing key"
    _ -> die "unexpected CBOR header in TextEnvelope"

die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure
