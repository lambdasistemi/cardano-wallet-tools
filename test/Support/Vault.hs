{- |
Module      : Support.Vault
Description : Oracles and producers for the vault specs
License     : Apache-2.0

Everything a vault spec compares against is obtained here from a
producer, never typed beside the assertion: key bytes and verification
keys come from the @cardano-cli@ fixture files, the vault plaintext
from stock @age@, the work factor from the age header, the signature
check from crypton. None of it calls the library under test.
-}
module Support.Vault
    ( -- * Fixtures
      readFixture
    , fixturePath
    , Envelope (..)
    , parseEnvelope
    , secretOfEnvelope
    , verificationKeyOfFixture
    , identityLabelsOfPayload

      -- * Keys
    , seedKey
    , seedEnvelope
    , keyFromSeed
    , publicOf
    , signatureVerifies
    , witnessOf
    , signsAs

      -- * Passphrases and work factors
    , passphrase
    , factor

      -- * Files and descriptors
    , withTempDir
    , withDescriptorOn
    , withPassphraseDescriptor
    , withEnv

      -- * Option parsing
    , parseArgs

      -- * Stock age
    , ageDecrypt
    , encryptAtFactor

      -- * Age header
    , headerStanzas
    , scryptWorkFactorOf

      -- * Pseudo-terminals
    , withPseudoTerminal
    , setEchoOn
    , echoIsOn
    , drain
    ) where

import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , Signer (..)
    , TxBodyBytes (..)
    )
import Cardano.Wallet.Tools.Vault.Passphrase
    ( Passphrase
    , mkPassphrase
    )
import Cardano.Wallet.Tools.Vault.Payload
    ( PaymentSigningKey
    , parseSigningKeyEnvelope
    , signerFromKey
    )
import Control.Exception (IOException, SomeException, bracket, try)
import Control.Exception qualified as Exception
import Control.Monad (unless, (>=>))
import Control.Monad.Trans.Except (runExceptT)
import Crypto.Age.Buffered qualified as Age
import Crypto.Age.Recipient (Recipients (..), ScryptRecipient (..))
import Crypto.Age.Scrypt
    ( WorkFactor
    , bytesToSalt
    , mkWorkFactor
    )
import Crypto.Age.Scrypt qualified as Scrypt (Passphrase (..))
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Data.Aeson (FromJSON (..), withObject, (.:))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Data.Word (Word8)
import Options.Applicative
    ( Parser
    , ParserResult (..)
    , defaultPrefs
    , execParserPure
    , info
    , renderFailure
    )
import System.Directory
    ( doesFileExist
    , getTemporaryDirectory
    , removePathForcibly
    )
import System.Environment
    ( getEnvironment
    , lookupEnv
    , setEnv
    , unsetEnv
    )
import System.Exit (ExitCode)
import System.FilePath ((</>))
import System.IO
    ( BufferMode (NoBuffering)
    , Handle
    , hClose
    , hSetBuffering
    )
import System.Posix.IO
    ( OpenMode (ReadOnly)
    , defaultFileFlags
    , fdToHandle
    , openFd
    )
import System.Posix.Temp (mkdtemp)
import System.Posix.Terminal
    ( TerminalMode (EnableEcho)
    , TerminalState (Immediately)
    , getTerminalAttributes
    , openPseudoTerminal
    , setTerminalAttributes
    , terminalMode
    , withMode
    )
import System.Posix.Types (Fd (..))
import System.Process
    ( CreateProcess (env)
    , proc
    , readCreateProcessWithExitCode
    )
import Test.Hspec (shouldBe, shouldSatisfy)

-- * Fixtures

-- | Where the committed fixtures live, relative to the package root.
fixtureRoot :: FilePath
fixtureRoot = "test/fixtures/vault"

-- | A fixture's path from a name below the fixture directory.
fixturePath :: FilePath -> FilePath
fixturePath name = fixtureRoot </> name

-- | A fixture's bytes; a missing file fails the example by name.
readFixture :: FilePath -> IO ByteString
readFixture name = do
    let path = fixturePath name
    present <- doesFileExist path
    unless present $
        fail $
            "fixture not found: "
                <> path
                <> " (the specs run from the package root)"
    BS.readFile path

-- | A @cardano-cli@ text envelope, read by the spec's own parser.
data Envelope = Envelope
    { envelopeType :: Text
    , envelopeCborHex :: Text
    }
    deriving stock (Eq, Show)

instance FromJSON Envelope where
    parseJSON = withObject "Envelope" $ \o ->
        Envelope <$> o .: "type" <*> o .: "cborHex"

parseEnvelope :: ByteString -> Either String Envelope
parseEnvelope = Aeson.eitherDecodeStrict'

{- | The 32 key bytes under the @5820@ CBOR header of an envelope's
@cborHex@.
-}
secretOfEnvelope :: Envelope -> Either String ByteString
secretOfEnvelope envelope = do
    raw <- B16.decode (TE.encodeUtf8 (envelopeCborHex envelope))
    case BS.splitAt 2 raw of
        (header, key)
            | header == BS.pack [0x58, 0x20] && BS.length key == 32 ->
                Right key
        _ -> Left "cborHex is not 5820 followed by 32 bytes"

-- | The 32 key bytes of a @.vkey@ (or @.skey@) fixture, read from its envelope.
verificationKeyOfFixture :: FilePath -> IO ByteString
verificationKeyOfFixture name =
    readFixture name
        >>= either fail pure . (parseEnvelope >=> secretOfEnvelope)

{- | The identity labels of a tx-sign payload, the keys of its
@identities@ object.
-}
identityLabelsOfPayload :: ByteString -> IO [Text]
identityLabelsOfPayload payload =
    case Aeson.decodeStrict' payload of
        Just (Aeson.Object top)
            | Just (Aeson.Object vault) <- KeyMap.lookup "cardanoTxSignVault" top
            , Just (Aeson.Object identities) <- KeyMap.lookup "identities" vault ->
                pure (Key.toText <$> KeyMap.keys identities)
        _ -> fail "the payload fixture has no identities object"

-- * Keys

-- | A 32-byte seed from a first byte, made at run time.
seedKey :: Word8 -> ByteString
seedKey first = BS.pack (first : replicate 31 0x2a)

-- | The @cardano-cli@ text envelope of a seed, built here.
seedEnvelope :: ByteString -> ByteString
seedEnvelope seed =
    "{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"spec\""
        <> ",\"cborHex\":\"5820"
        <> B16.encode seed
        <> "\"}"

-- | The library's key for a seed, through its envelope reader.
keyFromSeed :: ByteString -> PaymentSigningKey
keyFromSeed =
    either (error . ("keyFromSeed: " <>) . show) id
        . parseSigningKeyEnvelope
        . seedEnvelope

-- | The Ed25519 verification-key bytes of a 32-byte secret.
publicOf :: ByteString -> ByteString
publicOf secret = case Ed25519.secretKey secret of
    CryptoPassed key -> BA.convert (Ed25519.toPublic key)
    CryptoFailed e -> error ("publicOf: " <> show e)

-- | Whether a signature verifies under a verification key.
signatureVerifies :: ByteString -> ByteString -> ByteString -> Bool
signatureVerifies vkey message signature =
    case (Ed25519.publicKey vkey, Ed25519.signature signature) of
        (CryptoPassed key, CryptoPassed sig) ->
            Ed25519.verify key message sig
        _ -> False

-- | The witness a signer gives for a body.
witnessOf :: Signer IO -> ByteString -> IO DetachedWitness
witnessOf signer body = signTxBody signer (TxBodyBytes body)

{- | A key signs as the verification key expected: the witness carries
it, and its signature verifies.
-}
signsAs :: PaymentSigningKey -> ByteString -> IO ()
signsAs key expected = do
    witness <- witnessOf (signerFromKey key) body
    detachedWitnessVKey witness `shouldBe` expected
    detachedWitnessSignature witness
        `shouldSatisfy` signatureVerifies expected body
  where
    body = "the transaction body bytes"

-- * Passphrases and work factors

-- | A passphrase from bytes; an empty one fails the spec loudly.
passphrase :: ByteString -> Passphrase
passphrase =
    either (error . ("passphrase refused: " <>) . show) id . mkPassphrase

-- | A scrypt work factor for the specs.
factor :: Word8 -> WorkFactor
factor n =
    fromMaybe
        (error "Support.Vault.factor: out of range")
        (mkWorkFactor n)

-- * Files and descriptors

-- | A fresh directory, removed afterwards.
withTempDir :: String -> (FilePath -> IO a) -> IO a
withTempDir template action = do
    tmp <- getTemporaryDirectory
    bracket (mkdtemp (tmp </> template)) removePathForcibly action

{- | A read-only descriptor on a file. The code that reads it closes
it, as @--passphrase-fd@ hands over an inherited descriptor.
-}
withDescriptorOn :: FilePath -> (Int -> IO a) -> IO a
withDescriptorOn path action = do
    Fd n <- openFd path ReadOnly defaultFileFlags
    action (fromIntegral n)

-- | A descriptor positioned at the start of the given bytes.
withPassphraseDescriptor :: ByteString -> (Int -> IO a) -> IO a
withPassphraseDescriptor contents action =
    withTempDir "descriptor" $ \dir -> do
        let path = dir </> "passphrase"
        BS.writeFile path contents
        withDescriptorOn path action

-- * Environment

-- | Run an action with environment variables set, restored afterwards.
withEnv :: [(String, String)] -> IO a -> IO a
withEnv assignments action =
    bracket (traverse save assignments) (mapM_ restore) $ \_ -> do
        mapM_ (uncurry setEnv) assignments
        action
  where
    save (name, _) = (,) name <$> lookupEnv name
    restore (name, previous) = maybe (unsetEnv name) (setEnv name) previous

-- * Option parsing

-- | Run a parser over arguments; the rendered failure on refusal.
parseArgs :: Parser a -> [String] -> Either String a
parseArgs parser args =
    case execParserPure defaultPrefs (info parser mempty) args of
        Success a -> Right a
        Failure failure -> Left (fst (renderFailure failure "cwt"))
        CompletionInvoked _ -> Left "completion invoked"

-- * Stock age

{- | Stock @age@ decrypting a vault with a passphrase from its
environment; exit code, plaintext, stderr. A missing @age@ fails the
example: the interop proof never skips.
-}
ageDecrypt
    :: ByteString -> ByteString -> IO (ExitCode, ByteString, String)
ageDecrypt secret vault = withTempDir "age" $ \dir -> do
    let path = dir </> "vault.age"
    BS.writeFile path vault
    environment <- getEnvironment
    let process =
            (proc "age" ["-d", "-j", "batchpass", path])
                { env =
                    Just
                        ( ("AGE_PASSPHRASE", BC.unpack secret)
                            : filter ((/= "AGE_PASSPHRASE") . fst) environment
                        )
                }
    ran <- try (readCreateProcessWithExitCode process "")
    case ran of
        Left (e :: IOException) ->
            fail ("stock age could not be run (is age on PATH?): " <> show e)
        Right (code, out, err) -> pure (code, BC.pack out, err)

{- | Encrypt with the age library directly at a work factor, for vaults
the code under test must refuse or open. Independent of the seal under
test.
-}
encryptAtFactor :: Word8 -> ByteString -> ByteString -> IO ByteString
encryptAtFactor n secret plaintext = do
    salt <-
        maybe (fail "salt") pure (bytesToSalt (BS.replicate 16 0x5a))
    sealed <-
        runExceptT $
            Age.encrypt
                ( RecipientsScrypt
                    ScryptRecipient
                        { srPassphrase = Scrypt.Passphrase (BA.convert secret)
                        , srSalt = salt
                        , srWorkFactor = factor n
                        }
                )
                plaintext
    either (fail . show) pure sealed

-- * Age header

{- | The stanza lines of an age v1 header: each @->@ line before the
@---@ line.
-}
headerStanzas :: ByteString -> [ByteString]
headerStanzas =
    filter (BC.isPrefixOf "-> ")
        . takeWhile (not . BC.isPrefixOf "---")
        . drop 1
        . BC.lines

-- | The work factor an @-> scrypt <salt> <log2 N>@ stanza records.
scryptWorkFactorOf :: ByteString -> Maybe Int
scryptWorkFactorOf stanza = case BC.words stanza of
    ["->", "scrypt", _salt, n] -> fst <$> BC.readInt n
    _ -> Nothing

-- * Pseudo-terminals

{- | A pseudo-terminal with both ends unbuffered: master handle, slave
handle, slave descriptor. Closed afterwards.
-}
withPseudoTerminal :: (Handle -> Handle -> Fd -> IO a) -> IO a
withPseudoTerminal action =
    bracket open close $ \(master, slave, slaveFd) ->
        action master slave slaveFd
  where
    open = do
        (masterFd, slaveFd) <- openPseudoTerminal
        master <- fdToHandle masterFd
        slave <- fdToHandle slaveFd
        hSetBuffering master NoBuffering
        hSetBuffering slave NoBuffering
        pure (master, slave, slaveFd)
    close (master, slave, _) = do
        closeQuietly slave
        closeQuietly master
    closeQuietly h =
        Exception.catch (hClose h) (\(_ :: SomeException) -> pure ())

-- | Turn the terminal's echo explicitly on.
setEchoOn :: Fd -> IO ()
setEchoOn fd = do
    attributes <- getTerminalAttributes fd
    setTerminalAttributes fd (withMode attributes EnableEcho) Immediately

-- | Whether the terminal's echo is on.
echoIsOn :: Fd -> IO Bool
echoIsOn fd = terminalMode EnableEcho <$> getTerminalAttributes fd

-- | Whatever the master end has ready to read, without blocking.
drain :: Handle -> IO ByteString
drain master = do
    chunk <- BS.hGetNonBlocking master 4096
    if BS.null chunk then pure chunk else (chunk <>) <$> drain master
