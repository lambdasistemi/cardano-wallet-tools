{- |
Module      : Cardano.Wallet.Tools.Vault.Scrypt
Description : The passphrase vault: one binary age file, one scrypt stanza
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A vault of this kind is one binary age file whose only recipient is a
passphrase (scrypt). 'sealVault' records exactly the work factor it is
given; 'openVault' refuses a vault whose factor exceeds
'vaultWorkFactorCap'.

Calculations are values: 'openVault' is pure, and 'sealVault' declares
the one effect it has, drawing the salt.
-}
module Cardano.Wallet.Tools.Vault.Scrypt
    ( vaultWorkFactorCap
    , sealVault
    , openVault
    ) where

import Cardano.Wallet.Tools.Vault.File (VaultRefusal (..))
import Cardano.Wallet.Tools.Vault.Passphrase
    ( Passphrase
    , passphraseBytes
    )
import Cardano.Wallet.Tools.Vault.Payload
    ( IdentitySelector
    , OpenedKey
    , PaymentSigningKey
    , VaultPayloadRefusal (..)
    , decodeVaultPayload
    , encodeV1Payload
    )
import Control.Monad.Trans.Except (runExceptT)
import Crypto.Age.Buffered qualified as Age
import Crypto.Age.Identity (Identity (..), ScryptIdentity (..))
import Crypto.Age.Recipient (Recipients (..), ScryptRecipient (..))
import Crypto.Age.Scrypt
    ( WorkFactor
    , bytesToSalt
    , mkWorkFactor
    )
import Crypto.Age.Scrypt qualified as Scrypt (Passphrase (..))
import Crypto.Random (getRandomBytes)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty (..))

{- | The greatest scrypt work factor the CLI seals with and every
opening accepts: 18.
-}
vaultWorkFactorCap :: WorkFactor
vaultWorkFactorCap = case mkWorkFactor 18 of
    Just factor -> factor
    Nothing -> error "Vault.Scrypt.vaultWorkFactorCap: 18 is out of range"

{- | Seal a key into vault bytes: binary age, exactly one scrypt stanza
at the given work factor, v1 plaintext. Effect: the random salt.
-}
sealVault
    :: WorkFactor
    -> Passphrase
    -> PaymentSigningKey
    -> IO (Either VaultRefusal ByteString)
sealVault workFactor passphrase key = do
    saltBytes <- getRandomBytes 16
    case bytesToSalt saltBytes of
        Nothing -> pure (Left (VaultNotWritten "the vault salt could not be made"))
        Just salt -> do
            sealed <-
                runExceptT $
                    Age.encrypt
                        ( RecipientsScrypt
                            ScryptRecipient
                                { srPassphrase =
                                    Scrypt.Passphrase
                                        (BA.convert (passphraseBytes passphrase))
                                , srSalt = salt
                                , srWorkFactor = workFactor
                                }
                        )
                        (encodeV1Payload key)
            pure $
                either
                    (const (Left (VaultNotWritten "the seal failed")))
                    Right
                    sealed

{- | Open vault bytes with a passphrase: the signing key, or the one
opening refusal. Wrong passphrase, corrupt file, not a vault, a work
factor above the cap and a plaintext that is not a key all answer the
same refusal.
-}
openVault
    :: Maybe IdentitySelector
    -> Passphrase
    -> ByteString
    -> Either VaultRefusal OpenedKey
openVault selector passphrase vaultBytes =
    case Age.decrypt identities vaultBytes of
        Left _ -> Left VaultNotOpened
        Right plaintext -> case decodeVaultPayload selector plaintext of
            Right key -> Right key
            Left PayloadNotASigningKey -> Left VaultNotOpened
            Left refusal -> Left (VaultPayloadRefused refusal)
  where
    identities :: NonEmpty Identity
    identities =
        IdentityScrypt
            ScryptIdentity
                { siPassphrase =
                    Scrypt.Passphrase
                        (BA.convert (passphraseBytes passphrase))
                , siMaxWorkFactor = vaultWorkFactorCap
                }
            :| []
