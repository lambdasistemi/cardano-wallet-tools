{- |
Module      : Main
Description : A fake age plugin for the fido2-hmac name, for the specs
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Test double, not a product: a program that speaks the real age plugin
stdio protocol (C2SP @age-plugin.md@, state machines @recipient-v1@ and
@identity-v1@) so the client in @cwt@ and stock @age@ can be exercised
without an authenticator. The package never installs it under the
@age-plugin-fido2-hmac@ name; the specs link it under that name in a
directory of their own and put the directory on their own @PATH@.

The plugin is named by the name it is started under
(@age-plugin-NAME@). Each key is a 32-byte secret: the identity is the
secret, the recipient is a hash of it, and a file key wrapped for one
recipient unwraps only under the identity of that recipient.

@cwt-fake-fido2-plugin --keygen NAME LABEL@ prints the recipient and
the identity of the key named by @LABEL@, one per line.

Steering, by environment variables the spec sets:

* @CWT_FAKE_FIDO2_MESSAGE@: send this @msg@ before any work;
* @CWT_FAKE_FIDO2_SECRET_PROMPT@, @CWT_FAKE_FIDO2_SECRET_EXPECTED@:
  send @request-secret@ and fail unless the reply is exactly the
  expected secret;
* @CWT_FAKE_FIDO2_PUBLIC_PROMPT@, @CWT_FAKE_FIDO2_PUBLIC_EXPECTED@:
  the same for @request-public@;
* @CWT_FAKE_FIDO2_CONFIRM_PROMPT@: send @confirm@ and fail unless the
  reply is @ok yes@;
* @CWT_FAKE_FIDO2_UNKNOWN_COMMAND@: send a command the protocol does
  not define and fail unless the reply is @unsupported@;
* @CWT_FAKE_FIDO2_ERROR@: send @error internal@ with this message
  instead of working;
* @CWT_FAKE_FIDO2_ONLY_IN@: apply the steering above to this state
  machine only (@recipient-v1@ or @identity-v1@), the other works
  normally;
* @CWT_FAKE_FIDO2_EXIT_EARLY@: exit with status 3 before speaking;
* @CWT_FAKE_FIDO2_GARBAGE@: answer the first phase with text that is no
  stanza;
* @CWT_FAKE_FIDO2_LOG@: append what the plugin was started with and
  what it received to this file.
-}
module Main (main) where

import Codec.Binary.Bech32 qualified as Bech32
import Control.Monad (forM_, unless, when)
import Crypto.Cipher.ChaChaPoly1305 qualified as ChaCha
import Crypto.Error (CryptoFailable (..), throwCryptoError)
import Crypto.Hash (SHA256 (..), hashWith)
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.Random (getRandomBytes)
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding
    ( Base (Base16, Base64)
    , convertFromBase
    , convertToBase
    )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import System.Environment (getArgs, getProgName, lookupEnv)
import System.Exit (ExitCode (..), exitWith)
import System.IO
    ( BufferMode (BlockBuffering)
    , Handle
    , hFlush
    , hIsEOF
    , hPutStrLn
    , hSetBinaryMode
    , hSetBuffering
    , stderr
    , stdin
    , stdout
    )

-- * Stanzas

-- | One stanza of the plugin stream: a command, its arguments, its data.
data Stanza = Stanza
    { command :: ByteString
    , arguments :: [ByteString]
    , payload :: ByteString
    }

-- | Standard base64 without padding.
encodeB64 :: ByteString -> ByteString
encodeB64 = BC.filter (/= '=') . convertToBase Base64

-- | Standard base64 without padding, read back.
decodeB64 :: ByteString -> Maybe ByteString
decodeB64 text =
    either (const Nothing) Just . convertFromBase Base64 $
        text <> BC.replicate ((4 - BS.length text `mod` 4) `mod` 4) '='

-- | Write a stanza: the argument line, the body in 64-column lines.
writeStanza :: Handle -> Stanza -> IO ()
writeStanza h Stanza{command, arguments, payload} = do
    BS.hPut h ("-> " <> BC.unwords (command : arguments) <> "\n")
    let encoded = encodeB64 payload
        rows = chunksOf 64 encoded
    forM_ rows $ \row -> BS.hPut h (row <> "\n")
    when (null rows || BS.length (last rows) == 64) $ BS.hPut h "\n"
    hFlush h

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bytes
    | BS.null bytes = []
    | otherwise =
        let (row, rest) = BS.splitAt n bytes in row : chunksOf n rest

-- | The next stanza, or nothing at the end of the stream.
readStanza :: Handle -> IO (Maybe Stanza)
readStanza h = do
    line <- readLine
    case line of
        Nothing -> pure Nothing
        Just first -> case BC.stripPrefix "-> " first of
            Nothing -> failWith ("not a stanza line: " <> BC.unpack first)
            Just rest -> case BC.words rest of
                [] -> failWith "a stanza without a command"
                (cmd : args) -> do
                    rows <- bodyRows
                    case decodeB64 (BS.concat rows) of
                        Nothing -> failWith "a stanza body is not base64"
                        Just bytes -> pure (Just (Stanza cmd args bytes))
  where
    readLine = do
        atEnd <- hIsEOF h
        if atEnd then pure Nothing else Just <$> BC.hGetLine h
    bodyRows = do
        row <- readLine
        case row of
            Nothing -> failWith "the stream ended inside a stanza body"
            Just r
                | BS.length r < 64 -> pure [r]
                | otherwise -> (r :) <$> bodyRows

-- * Keys

hash256 :: ByteString -> ByteString
hash256 = BA.convert . hashWith SHA256

-- | The 32-byte secret of the key named by a label, for a plugin name.
identitySecret :: ByteString -> ByteString -> ByteString
identitySecret name label =
    hash256 ("cwt-fake-identity:" <> name <> ":" <> label)

-- | What a recipient is: a hash of the identity's secret.
recipientOf :: ByteString -> ByteString
recipientOf secret = hash256 ("cwt-fake-recipient:" <> secret)

-- | The short tag a stanza carries to say which recipient it is for.
fingerprintOf :: ByteString -> ByteString
fingerprintOf recipient =
    BS.take 4 (hash256 ("cwt-fake-fingerprint:" <> recipient))

wrapKeyOf :: ByteString -> ByteString
wrapKeyOf recipient = hash256 ("cwt-fake-wrap:" <> recipient)

recipientText :: ByteString -> ByteString -> Text
recipientText name = bech32 ("age1" <> name)

identityText :: ByteString -> ByteString -> Text
identityText name secret =
    T.toUpper (bech32 ("age-plugin-" <> name <> "-") secret)

bech32 :: ByteString -> ByteString -> Text
bech32 prefix bytes =
    case Bech32.humanReadablePartFromText (TE.decodeUtf8 prefix) of
        Right hrp -> Bech32.encodeLenient hrp (Bech32.dataPartFromBytes bytes)
        Left e -> error ("bech32 prefix: " <> show e)

-- | The 32 bytes behind a bech32 text of the given prefix.
unbech32 :: ByteString -> Text -> Maybe ByteString
unbech32 prefix text = do
    (hrp, dat) <- either (const Nothing) Just (Bech32.decodeLenient text)
    unless
        (Bech32.humanReadablePartToText hrp == TE.decodeUtf8 prefix)
        Nothing
    bytes <- Bech32.dataPartToBytes dat
    if BS.length bytes == 32 then Just bytes else Nothing

-- | ChaCha20-Poly1305 with a 12-byte nonce, tag appended.
seal :: ByteString -> ByteString -> ByteString -> ByteString
seal key nonce plaintext =
    let state =
            throwCryptoError (ChaCha.nonce12 nonce >>= ChaCha.initialize key)
        (ciphertext, state') = ChaCha.encrypt plaintext state
    in  ciphertext <> BA.convert (ChaCha.finalize state')

-- | The inverse of 'seal'; nothing when the tag does not verify.
unseal :: ByteString -> ByteString -> ByteString -> Maybe ByteString
unseal key nonce sealed = do
    let (ciphertext, tag) = BS.splitAt (BS.length sealed - 16) sealed
    when (BS.length sealed < 16) Nothing
    auth <- case Poly1305.authTag tag of
        CryptoPassed a -> Just a
        CryptoFailed _ -> Nothing
    state <- case ChaCha.nonce12 nonce >>= ChaCha.initialize key of
        CryptoPassed s -> Just s
        CryptoFailed _ -> Nothing
    let (plaintext, state') = ChaCha.decrypt ciphertext state
    if ChaCha.finalize state' == auth then Just plaintext else Nothing

-- * Entry

main :: IO ()
main = do
    hSetBinaryMode stdin True
    hSetBinaryMode stdout True
    hSetBuffering stdout (BlockBuffering Nothing)
    args <- getArgs
    progName <- getProgName
    let name =
            BC.pack (fromMaybe "fido2-hmac" (stripPrefix' "age-plugin-" progName))
    case args of
        ["--keygen", pluginName, label] -> keygen (BC.pack pluginName) (BC.pack label)
        ["--age-plugin=recipient-v1"] -> started progName "recipient-v1" >> recipientV1 name
        ["--age-plugin=identity-v1"] -> started progName "identity-v1" >> identityV1 name
        _ -> failWith ("unknown arguments: " <> unwords args)
  where
    stripPrefix' prefix s =
        if take (length prefix) s == prefix
            then Just (drop (length prefix) s)
            else Nothing

keygen :: ByteString -> ByteString -> IO ()
keygen name label = do
    let secret = identitySecret name label
    BC.putStrLn (TE.encodeUtf8 (recipientText name (recipientOf secret)))
    BC.putStrLn (TE.encodeUtf8 (identityText name secret))
    hFlush stdout

failWith :: String -> IO a
failWith message = do
    hPutStrLn stderr ("fake fido2 plugin: " <> message)
    exitWith (ExitFailure 1)

-- * Log

logLine :: String -> IO ()
logLine line = do
    target <- lookupEnv "CWT_FAKE_FIDO2_LOG"
    forM_ target $ \path -> appendFile path (line <> "\n")

started :: String -> String -> IO ()
started progName machine = do
    logLine ("invoked " <> progName <> " " <> machine)
    early <- lookupEnv "CWT_FAKE_FIDO2_EXIT_EARLY"
    forM_ early $ \_ -> exitWith (ExitFailure 3)

hex :: ByteString -> String
hex = BC.unpack . convertToBase Base16

-- * Conversation

-- | Read the first phase: every stanza up to @done@.
firstPhase :: IO [Stanza]
firstPhase = do
    garbage <- lookupEnv "CWT_FAKE_FIDO2_GARBAGE"
    forM_ garbage $ \_ -> do
        BC.hPutStr stdout "this is not a stanza\n"
        hFlush stdout
        exitWith (ExitFailure 4)
    go
  where
    go = do
        next <- readStanza stdin
        case next of
            Nothing -> failWith "the client closed the stream before done"
            Just s
                | command s == "done" -> pure []
                | otherwise -> do
                    logLine
                        ( "received "
                            <> BC.unpack (BC.unwords (command s : arguments s))
                        )
                    (s :) <$> go

-- | Send a command that wants a reply, and read the reply.
ask :: Stanza -> IO Stanza
ask s = do
    writeStanza stdout s
    reply <- readStanza stdin
    case reply of
        Nothing -> failWith "the client closed the stream awaiting a reply"
        Just r -> pure r

-- | Report an error to the client, finish the conversation, and stop.
refuse :: [ByteString] -> String -> IO a
refuse kind message = do
    _ <- ask (Stanza "error" kind (BC.pack message))
    writeStanza stdout (Stanza "done" [] "")
    exitWith (ExitFailure 1)

-- | The interactions the environment asks the plugin to attempt in a state machine.
steer :: String -> IO ()
steer machine = do
    only <- lookupEnv "CWT_FAKE_FIDO2_ONLY_IN"
    when (maybe True (== machine) only) steering

steering :: IO ()
steering = do
    failure <- lookupEnv "CWT_FAKE_FIDO2_ERROR"
    forM_ failure (refuse ["internal"])
    message <- lookupEnv "CWT_FAKE_FIDO2_MESSAGE"
    forM_ message $ \text -> do
        reply <- ask (Stanza "msg" [] (BC.pack text))
        unless (command reply == "ok") $ refuse ["internal"] "message refused"
    secretPrompt <- lookupEnv "CWT_FAKE_FIDO2_SECRET_PROMPT"
    expectedSecret <- lookupEnv "CWT_FAKE_FIDO2_SECRET_EXPECTED"
    forM_ secretPrompt $ \prompt -> do
        reply <- ask (Stanza "request-secret" [] (BC.pack prompt))
        let acceptable =
                command reply == "ok"
                    && maybe True ((== payload reply) . BC.pack) expectedSecret
        unless acceptable $ refuse ["internal"] "secret refused"
    publicPrompt <- lookupEnv "CWT_FAKE_FIDO2_PUBLIC_PROMPT"
    expectedPublic <- lookupEnv "CWT_FAKE_FIDO2_PUBLIC_EXPECTED"
    forM_ publicPrompt $ \prompt -> do
        reply <- ask (Stanza "request-public" [] (BC.pack prompt))
        let acceptable =
                command reply == "ok"
                    && maybe True ((== payload reply) . BC.pack) expectedPublic
        unless acceptable $ refuse ["internal"] "public value refused"
    confirmPrompt <- lookupEnv "CWT_FAKE_FIDO2_CONFIRM_PROMPT"
    forM_ confirmPrompt $ \prompt -> do
        reply <-
            ask
                ( Stanza
                    "confirm"
                    [encodeB64 "yes", encodeB64 "no"]
                    (BC.pack prompt)
                )
        unless (command reply == "ok" && arguments reply == ["yes"]) $
            refuse ["internal"] "confirmation refused"
    unknown <- lookupEnv "CWT_FAKE_FIDO2_UNKNOWN_COMMAND"
    forM_ unknown $ \name -> do
        reply <-
            ask (Stanza (BC.pack name) ["some", "arguments"] "some data")
        unless (command reply == "unsupported" && null (arguments reply)) $
            refuse ["internal"] "unknown command not answered unsupported"

-- * recipient-v1

recipientV1 :: ByteString -> IO ()
recipientV1 name = do
    phase <- firstPhase
    let recipientTexts =
            [ TE.decodeUtf8 text
            | Stanza "add-recipient" [text] _ <- phase
            ]
        fileKeys = [key | Stanza "wrap-file-key" _ key <- phase]
    forM_ fileKeys $ \key -> logLine ("wrap-file-key " <> hex key)
    steer "recipient-v1"
    when (null recipientTexts) $ refuse ["internal"] "no recipient"
    when (null fileKeys) $ refuse ["internal"] "no file key"
    let parsed = zip [0 :: Int ..] (map (unbech32 ("age1" <> name)) recipientTexts)
    forM_ parsed $ \(index, parsedRecipient) ->
        when (null parsedRecipient) $
            refuse
                ["recipient", BC.pack (show index)]
                "not a recipient of this plugin"
    let recipients = mapMaybe snd parsed
    forM_ (zip [0 :: Int ..] fileKeys) $ \(fileIndex, fileKey) ->
        forM_ recipients $ \recipient -> do
            nonce <- getRandomBytes 12
            let wrapped = nonce <> seal (wrapKeyOf recipient) nonce fileKey
            reply <-
                ask
                    ( Stanza
                        "recipient-stanza"
                        [ BC.pack (show fileIndex)
                        , name
                        , encodeB64 (fingerprintOf recipient)
                        ]
                        wrapped
                    )
            unless (command reply == "ok") $
                failWith "the client did not accept a stanza"
    writeStanza stdout (Stanza "done" [] "")

-- * identity-v1

identityV1 :: ByteString -> IO ()
identityV1 name = do
    phase <- firstPhase
    let secrets =
            mapMaybe
                ( \case
                    Stanza "add-identity" [text] _ ->
                        unbech32
                            ("age-plugin-" <> name <> "-")
                            (TE.decodeUtf8 text)
                    _ -> Nothing
                )
                phase
        identityCount = length [() | Stanza "add-identity" _ _ <- phase]
        stanzas =
            [ (fileIndex, args, wrapped)
            | Stanza "recipient-stanza" (indexText : tag : args) wrapped <- phase
            , tag == name
            , Just (fileIndex, "") <- [BC.readInt indexText]
            ]
    steer "identity-v1"
    when (length secrets /= identityCount) $
        refuse ["internal"] "not an identity of this plugin"
    let unwrapped =
            [ (fileIndex, fileKey)
            | (fileIndex, args, wrapped) <- stanzas
            , secret <- secrets
            , let recipient = recipientOf secret
            , args == [encodeB64 (fingerprintOf recipient)]
            , BS.length wrapped >= 12
            , let (nonce, sealed) = BS.splitAt 12 wrapped
            , Just fileKey <- [unseal (wrapKeyOf recipient) nonce sealed]
            ]
        firstPerFile =
            [ match
            | fileIndex <- uniqueIndexes (map (\(i, _, _) -> i) stanzas)
            , match : _ <- [[m | m@(i, _) <- unwrapped, i == fileIndex]]
            ]
    forM_ firstPerFile $ \(fileIndex, fileKey) -> do
        logLine ("unwrapped " <> hex fileKey)
        reply <- ask (Stanza "file-key" [BC.pack (show fileIndex)] fileKey)
        unless (command reply == "ok") $
            failWith "the client did not accept a file key"
    writeStanza stdout (Stanza "done" [] "")
  where
    uniqueIndexes = foldr (\i seen -> if i `elem` seen then seen else i : seen) []
