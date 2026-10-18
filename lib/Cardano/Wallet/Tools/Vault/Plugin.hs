{- |
Module      : Cardano.Wallet.Tools.Vault.Plugin
Description : The client side of the age plugin protocol
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

An age file whose file key is wrapped by programs other than @age@: the
client side of the age plugin stdio protocol (C2SP @age-plugin.md@).
'sealToPlugins' runs the @recipient-v1@ state machine of each plugin a
recipient names to wrap a fresh file key, and frames a binary age v1
file around the stanzas the plugins return. 'openWithPlugins' runs the
@identity-v1@ state machine to unwrap the file key from the header
stanzas, checks the header MAC and decrypts the payload.

The plugin of a recipient or identity is named by its encoding, as age
names it: the recipient @age1NAME1…@ and the identity
@AGE-PLUGIN-NAME-1…@ are for the binary @age-plugin-NAME@ on the
@PATH@. Whatever the plugin asks of the person at the terminal goes
through a 'PluginUi', and a command the client does not know is
answered @unsupported@. No secret, file key or key is shown: a secret
the interface returns goes to the plugin and is dropped, and a refusal
carries what the plugin said and nothing else.
-}
module Cardano.Wallet.Tools.Vault.Plugin
    ( -- * Recipients and identities
      PluginRecipient
    , PluginIdentity
    , parsePluginRecipient
    , parsePluginIdentity
    , pluginRecipientName
    , pluginRecipientText
    , pluginIdentityName
    , pluginIdentityText
    , pluginBinaryName

      -- * Interaction
    , PluginUi (..)
    , refusingPluginUi

      -- * Sealing and opening
    , sealToPlugins
    , openWithPlugins

      -- * Refusals
    , PluginRefusal (..)
    , renderPluginRefusal
    ) where

import Cardano.Wallet.Tools.Vault.Plugin.Payload
    ( openPayload
    , sealPayload
    )
import Cardano.Wallet.Tools.Vault.Plugin.Process
    ( Wire
    , findPluginBinary
    , receiveStanza
    , sendStanza
    , withPlugin
    )
import Codec.Binary.Bech32 qualified as Bech32
import Control.Applicative ((<|>))
import Control.Monad (guard, unless)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except
    ( ExceptT (..)
    , runExceptT
    , throwE
    )
import Crypto.Age.Header
    ( Header (..)
    , Stanza (..)
    , computeHeaderMac
    , headerBuilder
    , headerParser
    )
import Crypto.Age.Key
    ( FileKey
    , bytesToFileKey
    , fileKeyToBytes
    , generateFileKey
    , generatePayloadKeyNonce
    )
import Data.Attoparsec.ByteString (IResult (..), parse)
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding (Base (Base64), convertFromBase)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Builder qualified as Builder
import Data.ByteString.Char8 qualified as BC
import Data.ByteString.Lazy qualified as BSL
import Data.Char (isAlphaNum, isAscii, isControl)
import Data.Either (lefts, rights)
import Data.List (nub)
import Data.List.NonEmpty (NonEmpty (..))
import Data.List.NonEmpty qualified as NE
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Text.Encoding.Error (lenientDecode)
import System.Exit (ExitCode (..))

-- | A recipient of a plugin: its text and the plugin it names.
data PluginRecipient = PluginRecipient
    { recipientText :: Text
    , recipientPlugin :: Text
    }
    deriving stock (Eq, Ord, Show)

-- | An identity of a plugin: its text and the plugin it names. It is never shown.
data PluginIdentity = PluginIdentity
    { identityText :: Text
    , identityPlugin :: Text
    }
    deriving stock (Eq, Ord)

instance Show PluginIdentity where
    show _ = "<plugin identity>"

{- | How the client talks to the person at the terminal. A request the
interface cannot serve answers 'Nothing' and the plugin is told it
failed.
-}
data PluginUi = PluginUi
    { uiMessage :: Text -> IO ()
    -- ^ show a message
    , uiRequestPublic :: Text -> IO (Maybe Text)
    -- ^ ask for a public value, given the prompt
    , uiRequestSecret :: Text -> IO (Maybe ByteString)
    -- ^ ask for a secret, given the prompt; it is returned to the plugin and not kept
    , uiConfirm :: Text -> Text -> Maybe Text -> IO (Maybe Bool)
    -- ^ ask to choose: the prompt, the yes choice, an optional no choice
    }

-- | A user interface that refuses every request and drops messages.
refusingPluginUi :: PluginUi
refusingPluginUi =
    PluginUi
        { uiMessage = \_ -> pure ()
        , uiRequestPublic = \_ -> pure Nothing
        , uiRequestSecret = \_ -> pure Nothing
        , uiConfirm = \_ _ _ -> pure Nothing
        }

{- | Why a plugin operation was refused. None carries a file key, a
secret or key bytes.
-}
data PluginRefusal
    = -- | the binary @age-plugin-NAME@ is not on the PATH, naming it
      PluginBinaryNotFound Text
    | -- | the plugin reported an error, or stopped with one; its message
      PluginFailed Text
    | -- | the plugin did not follow the protocol, saying how
      PluginProtocolViolation Text
    | -- | the plugins ran and none unwrapped a file key from the stanzas
      PluginNoStanzaUnwrapped
    | -- | not an age v1 file, or its header or payload does not authenticate
      PluginFileRefused
    deriving stock (Eq, Show)

-- | One line naming the refusal, carrying no secret.
renderPluginRefusal :: PluginRefusal -> Text
renderPluginRefusal = \case
    PluginBinaryNotFound binary ->
        "plugin not found on the PATH: " <> oneLine binary
    PluginFailed message -> "plugin failed: " <> oneLine message
    PluginProtocolViolation what ->
        "plugin protocol violation: " <> oneLine what
    PluginNoStanzaUnwrapped -> "no plugin could unwrap the file key"
    PluginFileRefused ->
        "not an age v1 file, or its header or payload does not authenticate"

-- | A message on one line, control characters made spaces.
oneLine :: Text -> Text
oneLine = T.strip . T.map (\c -> if isControl c then ' ' else c)

pluginRecipientName :: PluginRecipient -> Text
pluginRecipientName = recipientPlugin

pluginRecipientText :: PluginRecipient -> Text
pluginRecipientText = recipientText

pluginIdentityName :: PluginIdentity -> Text
pluginIdentityName = identityPlugin

pluginIdentityText :: PluginIdentity -> Text
pluginIdentityText = identityText

-- | The binary of a plugin: @age-plugin-NAME@.
pluginBinaryName :: Text -> Text
pluginBinaryName name = "age-plugin-" <> name

-- | A plugin name: letters, digits and @-_.+@, and not empty.
validName :: Text -> Bool
validName name =
    not (T.null name)
        && T.all
            (\c -> isAscii c && (isAlphaNum c || c `elem` ("-_.+" :: String)))
            name

{- | The recipient of a Bech32 text with the human-readable part
@age1NAME@, naming the plugin NAME.
-}
parsePluginRecipient :: Text -> Maybe PluginRecipient
parsePluginRecipient text = do
    (hrp, _) <- either (const Nothing) Just (Bech32.decodeLenient text)
    name <- T.stripPrefix "age1" (Bech32.humanReadablePartToText hrp)
    guard (validName name)
    pure (PluginRecipient text (T.toLower name))

{- | The identity of a Bech32 text with the human-readable part
@AGE-PLUGIN-NAME-@, naming the plugin NAME.
-}
parsePluginIdentity :: Text -> Maybe PluginIdentity
parsePluginIdentity text = do
    (hrp, _) <- either (const Nothing) Just (Bech32.decodeLenient text)
    name <-
        T.stripPrefix "age-plugin-" (Bech32.humanReadablePartToText hrp)
            >>= T.stripSuffix "-"
    guard (validName name)
    pure (PluginIdentity text (T.toLower name))

-- * Conversations

type Conversation = ExceptT PluginRefusal IO

-- | Send a stanza the plugin must be able to read.
send :: Wire -> Stanza -> Conversation ()
send wire stanza = do
    sent <- liftIO (sendStanza wire stanza)
    unless sent $
        throwE (PluginProtocolViolation "the plugin stopped reading")

-- | The next command of the plugin.
receive :: Wire -> Conversation Stanza
receive wire =
    liftIO (receiveStanza wire)
        >>= maybe
            ( throwE
                ( PluginProtocolViolation
                    "the plugin's output is no stanza or ended early"
                )
            )
            pure

command :: ByteString -> [ByteString] -> ByteString -> Stanza
command tag args body = Stanza{sTag = tag, sArgs = args, sBody = body}

{- | Answer a command that asks something of the person: nothing for
commands that do not.
-}
interaction :: PluginUi -> Stanza -> IO (Maybe Stanza)
interaction ui stanza = case sTag stanza of
    "msg" -> do
        uiMessage ui (decodeText (sBody stanza))
        pure (Just ok)
    "request-public" ->
        Just
            . maybe failed (command "ok" [] . TE.encodeUtf8)
            <$> uiRequestPublic ui (decodeText (sBody stanza))
    "request-secret" ->
        Just
            . maybe failed (command "ok" [])
            <$> uiRequestSecret ui (decodeText (sBody stanza))
    "confirm" -> case traverse decodeBase64 (sArgs stanza) of
        Just (yes : rest) | length rest <= 1 -> do
            let no = listToMaybe rest
            choice <-
                uiConfirm
                    ui
                    (decodeText (sBody stanza))
                    (decodeText yes)
                    (decodeText <$> no)
            pure . Just $ case (choice, no) of
                (Just True, _) -> command "ok" ["yes"] ""
                (Just False, Just _) -> command "ok" ["no"] ""
                _ -> failed
        _ -> pure (Just failed)
    _ -> pure Nothing
  where
    ok = command "ok" [] ""
    failed = command "fail" [] ""

decodeText :: ByteString -> Text
decodeText = TE.decodeUtf8With lenientDecode

decodeBase64 :: ByteString -> Maybe ByteString
decodeBase64 text =
    either (const Nothing) Just . convertFromBase Base64 $
        text <> BC.replicate ((4 - BS.length text `mod` 4) `mod` 4) '='

{- | Run a state machine of a plugin: find its binary, send the first
phase, answer the plugin's commands until it is done. The commands the
conversation does not take are the interactions, answered here; an
unknown one is answered @unsupported@.
-}
converse
    :: PluginUi
    -> Text
    -> String
    -> [Stanza]
    -> (Wire -> Stanza -> Conversation (Maybe a))
    -> Conversation ([a], Maybe ExitCode)
converse ui name machine phase handle = do
    let binary = pluginBinaryName name
    path <-
        liftIO (findPluginBinary (T.unpack binary))
            >>= maybe (throwE (PluginBinaryNotFound binary)) pure
    (result, status) <-
        liftIO . withPlugin path machine $ \wire -> runExceptT $ do
            mapM_ (send wire) phase
            send wire (command "done" [] "")
            loop wire []
    outcome <- ExceptT (pure result)
    pure (outcome, status)
  where
    loop wire taken = do
        stanza <- receive wire
        case sTag stanza of
            "done" -> pure (reverse taken)
            _ -> do
                answered <- liftIO (interaction ui stanza)
                case answered of
                    Just reply -> send wire reply >> loop wire taken
                    Nothing -> do
                        handled <- handle wire stanza
                        loop wire (maybe taken (: taken) handled)

-- | Plugin error messages, from the @error@ commands of a conversation.
errorMessage :: Stanza -> Text
errorMessage = decodeText . sBody

-- * Sealing

{- | Seal a plaintext to the recipients: a fresh file key is wrapped by
the plugin of each recipient, and the stanzas framed in a binary age v1
file with the header MAC and the payload. Effects: the file key and the
payload nonce from the system's entropy, one child process per plugin.
-}
sealToPlugins
    :: PluginUi
    -> NonEmpty PluginRecipient
    -> ByteString
    -> IO (Either PluginRefusal ByteString)
sealToPlugins ui recipients plaintext = runExceptT $ do
    fileKey <- liftIO generateFileKey
    nonce <- liftIO generatePayloadKeyNonce
    stanzaGroups <-
        mapM (wrapWithPlugin ui fileKey) (groupByPlugin recipients)
    stanzas <-
        maybe
            (throwE (PluginProtocolViolation "the plugins wrapped no file key"))
            pure
            (NE.nonEmpty (concat stanzaGroups))
    payload <-
        maybe
            (throwE (PluginProtocolViolation "the payload is too long"))
            pure
            (sealPayload fileKey nonce plaintext)
    let header = Header stanzas (computeHeaderMac fileKey stanzas)
    pure (strict (headerBuilder header) <> payload)
  where
    strict = BSL.toStrict . Builder.toLazyByteString

-- | The recipients of each plugin, the plugins in order of first appearance.
groupByPlugin
    :: NonEmpty PluginRecipient -> [(Text, NonEmpty PluginRecipient)]
groupByPlugin recipients =
    [ (name, NE.fromList (filter ((== name) . recipientPlugin) listed))
    | name <- nub (recipientPlugin <$> listed)
    ]
  where
    listed = NE.toList recipients

-- | Wrap the file key to the recipients of one plugin; the stanzas it returns.
wrapWithPlugin
    :: PluginUi
    -> FileKey
    -> (Text, NonEmpty PluginRecipient)
    -> Conversation [Stanza]
wrapWithPlugin ui fileKey (name, recipients) = do
    (replies, status) <-
        converse
            ui
            name
            "recipient-v1"
            ( [ command "add-recipient" [TE.encodeUtf8 (recipientText r)] ""
              | r <- NE.toList recipients
              ]
                <> [command "wrap-file-key" [] (BA.convert (fileKeyToBytes fileKey))]
            )
            collect
    let failures = lefts replies
        stanzas = rights replies
    case (failures, status) of
        (message : _, _) -> throwE (PluginFailed message)
        (_, Just (ExitFailure code)) ->
            throwE
                ( PluginFailed ("the plugin stopped with status " <> T.pack (show code))
                )
        _ -> pure ()
    pure stanzas
  where
    collect wire stanza = case sTag stanza of
        "recipient-stanza" -> do
            send wire (command "ok" [] "")
            case sArgs stanza of
                "0" : tag : args ->
                    pure
                        ( Just (Right (Stanza{sTag = tag, sArgs = args, sBody = sBody stanza}))
                        )
                _ -> throwE (PluginProtocolViolation "a stanza of no file or no type")
        "error" -> do
            send wire (command "ok" [] "")
            pure (Just (Left (errorMessage stanza)))
        _ -> do
            send wire (command "unsupported" [] "")
            pure Nothing

-- * Opening

{- | Open an age file with the identities: the plugin of each identity is
asked to unwrap the file key from the header stanzas, and the first file
key that authenticates the header decrypts the payload. Effects: one
child process per plugin.
-}
openWithPlugins
    :: PluginUi
    -> NonEmpty PluginIdentity
    -> ByteString
    -> IO (Either PluginRefusal ByteString)
openWithPlugins ui identities ageFile = runExceptT $ do
    (header, payload) <- case parse headerParser ageFile of
        Done rest h -> pure (h, rest)
        _ -> throwE PluginFileRefused
    let groups = groupIdentities identities
    fileKey <- findFileKey ui groups (hStanzas header)
    unless (computeHeaderMac fileKey (hStanzas header) == hMac header) $
        throwE PluginFileRefused
    maybe (throwE PluginFileRefused) pure (openPayload fileKey payload)

{- | The first file key a plugin unwraps from the stanzas. A plugin that
is not installed ends the search; a plugin that failed is remembered and
the next one tried.
-}
findFileKey
    :: PluginUi
    -> [(Text, NonEmpty PluginIdentity)]
    -> NonEmpty Stanza
    -> Conversation FileKey
findFileKey ui groups stanzas = go groups Nothing
  where
    go [] problem = throwE (fromMaybe PluginNoStanzaUnwrapped problem)
    go (group : more) problem = do
        attempt <- liftIO (runExceptT (unwrapWithPlugin ui group stanzas))
        case attempt of
            Right (Just fileKey) -> pure fileKey
            Right Nothing -> go more problem
            Left refusal@(PluginBinaryNotFound _) -> throwE refusal
            Left refusal -> go more (problem <|> Just refusal)

-- | The identities of each plugin, the plugins in order of first appearance.
groupIdentities
    :: NonEmpty PluginIdentity -> [(Text, NonEmpty PluginIdentity)]
groupIdentities identities =
    [ (name, NE.fromList (filter ((== name) . identityPlugin) listed))
    | name <- nub (identityPlugin <$> listed)
    ]
  where
    listed = NE.toList identities

{- | Ask the plugin of some identities to unwrap the file key from the
stanzas of a header: the file key, if it found one.
-}
unwrapWithPlugin
    :: PluginUi
    -> (Text, NonEmpty PluginIdentity)
    -> NonEmpty Stanza
    -> Conversation (Maybe FileKey)
unwrapWithPlugin ui (name, identities) stanzas = do
    (replies, _) <-
        converse
            ui
            name
            "identity-v1"
            ( [ command "add-identity" [TE.encodeUtf8 (identityText i)] ""
              | i <- NE.toList identities
              ]
                <> [ command "recipient-stanza" ("0" : sTag s : sArgs s) (sBody s)
                   | s <- NE.toList stanzas
                   ]
            )
            collect
    let keys = rights replies
        failures = lefts replies
    case (keys, failures) of
        (bytes : _, _) -> case bytesToFileKey (BA.convert bytes) of
            Just fileKey -> pure (Just fileKey)
            Nothing -> throwE (PluginProtocolViolation "a file key of the wrong length")
        ([], message : _) -> throwE (PluginFailed message)
        ([], []) -> pure Nothing
  where
    collect wire stanza = case sTag stanza of
        "file-key" -> do
            send wire (command "ok" [] "")
            pure (Just (Right (sBody stanza)))
        "error" -> do
            send wire (command "ok" [] "")
            pure (Just (Left (errorMessage stanza)))
        _ -> do
            send wire (command "unsupported" [] "")
            pure Nothing
