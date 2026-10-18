{- |
Module      : Support.Fido2
Description : Keys, vaults and user interfaces for the FIDO2 specs
License     : Apache-2.0

Small producers and recorders the FIDO2 specs share. A key is made from
a seed at run time; a recording user interface notes what the client
asked and answers with what the example chose; the checks that two keys
are the same compare the v1 plaintext the library writes for them.
-}
module Support.Fido2
    ( -- * Keys and key pairs
      plainKey
    , goldenKey
    , paymentKey
    , changedAt
    , recipientsOf
    , identitiesOf
    , identityFileOf

      -- * Vaults
    , sealedTo
    , openedBy
    , sameKey
    , isNotOpened
    , isPluginMissing

      -- * Recording user interface
    , UiEvent (..)
    , Answers (..)
    , noAnswers
    , recordingUi

      -- * Time
    , within
    ) where

import Cardano.Wallet.Tools.Vault.Fido2
import Cardano.Wallet.Tools.Vault.File (VaultRefusal (..))
import Cardano.Wallet.Tools.Vault.Payload
    ( OpenedKey
    , PaymentSigningKey
    , encodeV1Payload
    , parseSigningKeyEnvelope
    )
import Cardano.Wallet.Tools.Vault.Plugin
    ( PluginUi (..)
    , refusingPluginUi
    )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.List.NonEmpty (NonEmpty (..))
import Data.List.NonEmpty qualified as NE
import Data.Text (Text)
import Support.FakePlugin (Keypair (..), identityFileBytes)
import Support.Vault
    ( encodedV1Of
    , keyFromSeed
    , readFixture
    , seedKey
    )
import System.Timeout (timeout)
import Test.Hspec (shouldBe)

-- | A key made at run time from a first seed byte.
plainKey :: (Integral a) => a -> PaymentSigningKey
plainKey n = keyFromSeed (seedKey (fromIntegral n))

-- | The key of the golden fixture, read from its @cardano-cli@ envelope.
goldenKey :: IO PaymentSigningKey
goldenKey =
    readFixture "golden/payment.skey"
        >>= either (fail . show) pure . parseSigningKeyEnvelope

-- | The recipients of key pairs, refused loudly when one is not valid.
recipientsOf :: NonEmpty Keypair -> NonEmpty Fido2Recipient
recipientsOf = fmap $ \pair ->
    either (error . show) id (parseFido2Recipient (keypairRecipient pair))

-- | The identities of key pairs, read as an identity file reads them.
identitiesOf :: NonEmpty Keypair -> NonEmpty Fido2Identity
identitiesOf =
    either (error . show) id
        . parseFido2Identities
        . identityFileBytes
        . NE.toList

-- | An identity file holding the identities of the key pairs.
identityFileOf :: NonEmpty Keypair -> ByteString
identityFileOf = identityFileBytes . NE.toList

-- | A vault of a key sealed to key pairs; a refusal fails the example.
sealedTo :: NonEmpty Keypair -> PaymentSigningKey -> IO ByteString
sealedTo pairs key =
    sealFido2Vault refusingPluginUi (recipientsOf pairs) key
        >>= either (fail . ("sealing refused: " <>) . show) pure

-- | A vault opened with one key pair's identity.
openedBy
    :: Keypair -> ByteString -> IO (Either Fido2Refusal OpenedKey)
openedBy pair =
    openFido2Vault refusingPluginUi (identitiesOf (pair :| []))

-- | An opening is the key of the given plain key, byte for byte.
sameKey :: Either Fido2Refusal OpenedKey -> PaymentSigningKey -> IO ()
sameKey opened key = case opened of
    Left refusal -> fail ("expected the key, got " <> show refusal)
    Right found -> encodedV1Of found `shouldBe` Just (encodeV1Payload key)

-- | The one opening refusal, whatever the way the vault did not open.
isNotOpened :: Either Fido2Refusal a -> Bool
isNotOpened = \case
    Left (Fido2VaultRefused VaultNotOpened) -> True
    _ -> False

-- | The refusal naming a plugin binary that is not on the PATH.
isPluginMissing :: Text -> Either Fido2Refusal a -> Bool
isPluginMissing binary = \case
    Left (Fido2PluginMissing named) -> named == binary
    _ -> False

-- | What the client asked of the person at the terminal.
data UiEvent
    = Message Text
    | AskedPublic Text
    | AskedSecret Text
    | AskedConfirm Text Text (Maybe Text)
    deriving stock (Eq, Show)

-- | What the example answers when asked. @Nothing@ refuses.
data Answers = Answers
    { answerPublic :: Maybe Text
    , answerSecret :: Maybe ByteString
    , answerConfirm :: Maybe Bool
    }

-- | Refuse every request.
noAnswers :: Answers
noAnswers = Answers Nothing Nothing Nothing

{- | A user interface that notes every request, never a secret, and
answers as told; and the events it noted, in order.
-}
recordingUi :: Answers -> IO (PluginUi, IO [UiEvent])
recordingUi answers = do
    noted <- newIORef []
    let note event = modifyIORef' noted (event :)
    pure
        ( refusingPluginUi
            { uiMessage = note . Message
            , uiRequestPublic = \prompt ->
                note (AskedPublic prompt) >> pure (answerPublic answers)
            , uiRequestSecret = \prompt ->
                note (AskedSecret prompt) >> pure (answerSecret answers)
            , uiConfirm = \prompt yes no ->
                note (AskedConfirm prompt yes no)
                    >> pure (answerConfirm answers)
            }
        , reverse <$> readIORef noted
        )

-- | A hang guard, not a timing assertion: the example fails, not stalls.
within :: IO a -> IO a
within action =
    timeout 60000000 action
        >>= maybe (fail "the exchange stalled") pure

-- | The key of the @cardano-cli@ payment fixture pair.
paymentKey :: IO PaymentSigningKey
paymentKey =
    readFixture "payment.skey"
        >>= either (fail . show) pure . parseSigningKeyEnvelope

-- | The bytes with the one at a position changed.
changedAt :: Int -> ByteString -> ByteString
changedAt position bytes =
    BS.take position bytes
        <> BS.singleton (BS.index bytes position + 1)
        <> BS.drop (position + 1) bytes
