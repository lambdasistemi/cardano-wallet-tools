module Cardano.Wallet.Tools.Vault
    ( VaultError (..)
    , VaultPassphrase
    , WorkFactor
    , mkVaultPassphrase
    , encryptVault
    , decryptVault
    , defaultWorkFactor
    , renderVaultError
    ) where

import Control.Monad.Trans.Except (runExceptT)
import Crypto.Age.Buffered qualified as Age
import Crypto.Age.Identity (Identity (..), ScryptIdentity (..))
import Crypto.Age.Recipient (Recipients (..), ScryptRecipient (..))
import Crypto.Age.Scrypt
    ( Passphrase (..)
    , WorkFactor
    , bytesToSalt
    , mkWorkFactor
    )
import Crypto.Random (getRandomBytes)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)

newtype VaultPassphrase = VaultPassphrase Passphrase
    deriving stock (Eq)

data VaultError
    = VaultEmptyPassphrase
    | VaultSaltError
    | VaultEncryptError
    | VaultDecryptError
    deriving stock (Eq, Show)

-- | Maximum age scrypt work factor accepted on decrypt (DoS bound).
defaultWorkFactor :: WorkFactor
defaultWorkFactor = case mkWorkFactor 18 of
    Just wf -> wf
    Nothing -> error "Cardano.Wallet.Tools.Vault.defaultWorkFactor: impossible"

mkVaultPassphrase :: ByteString -> Either VaultError VaultPassphrase
mkVaultPassphrase raw
    | BS.null raw = Left VaultEmptyPassphrase
    | otherwise = Right $ VaultPassphrase $ Passphrase (BA.convert raw)

encryptVault
    :: WorkFactor
    -> VaultPassphrase
    -> ByteString
    -> IO (Either VaultError ByteString)
encryptVault workFactor (VaultPassphrase passphrase) plaintext = do
    saltBytes <- getRandomBytes 16
    case bytesToSalt saltBytes of
        Nothing -> pure $ Left VaultSaltError
        Just salt -> do
            result <-
                runExceptT $
                    Age.encrypt
                        ( RecipientsScrypt
                            ScryptRecipient
                                { srPassphrase = passphrase
                                , srSalt = salt
                                , srWorkFactor = workFactor
                                }
                        )
                        plaintext
            pure $ either (const $ Left VaultEncryptError) Right result

decryptVault
    :: VaultPassphrase -> ByteString -> Either VaultError ByteString
decryptVault (VaultPassphrase passphrase) ciphertext =
    either (const $ Left VaultDecryptError) Right $
        Age.decrypt identities ciphertext
  where
    identities :: NonEmpty Identity
    identities =
        IdentityScrypt
            ScryptIdentity
                { siPassphrase = passphrase
                , siMaxWorkFactor = defaultWorkFactor
                }
            :| []

renderVaultError :: VaultError -> Text
renderVaultError = \case
    VaultEmptyPassphrase -> "vault passphrase is empty"
    VaultSaltError -> "failed to generate vault salt"
    VaultEncryptError -> "failed to encrypt vault"
    VaultDecryptError -> "failed to decrypt vault — wrong passphrase?"
