{- |
Module      : Cardano.Wallet.Tools.Sign
Description : Key-free signing boundary.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Pure signing surface for wallet integrations. Backends receive opaque
transaction-body bytes and return one detached vkey witness without
forcing key handling, IO, or ledger types into the shared core.
-}
module Cardano.Wallet.Tools.Sign
    ( -- * Signing boundary
      TxBodyBytes (..)
    , Signer (..)

      -- * Witness attachment
    , AttachWitnessError (..)
    , attachWitnesses
    , transactionBodyBytes

      -- * Detached witnesses
    , DetachedWitness (..)
    , WitnessDecodeError (..)
    , decodeDetachedWitness
    , encodeDetachedWitness
    , encodeShelleyWitnessEnvelope
    ) where

import Cardano.Wallet.Tools.Sign.AttachWitness
import Cardano.Wallet.Tools.Sign.Witness

-- | Effect-polymorphic signer boundary.
newtype Signer m = Signer
    { signTxBody :: TxBodyBytes -> m DetachedWitness
    }
