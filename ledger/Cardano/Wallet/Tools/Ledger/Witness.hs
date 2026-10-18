{- |
Module      : Cardano.Wallet.Tools.Ledger.Witness
Description : Ledger-typed detached witnesses
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

A detached witness over a ledger transaction: signed by an Ed25519 key
over the hash of the transaction's body, and assembled back into a
transaction that keeps the body bytes and so the identity. Signing
changes only the witness set.
-}
module Cardano.Wallet.Tools.Ledger.Witness
    ( detachedWitness
    , assembleWitnessed
    ) where

import Cardano.Crypto.DSIGN
    ( Ed25519DSIGN
    , SignKeyDSIGN
    , SignedDSIGN (..)
    , deriveVerKeyDSIGN
    , rawDeserialiseSigDSIGN
    , rawDeserialiseVerKeyDSIGN
    , rawSerialiseSigDSIGN
    , rawSerialiseVerKeyDSIGN
    )
import Cardano.Ledger.Api.Tx (addrTxWitsL, txIdTx, witsTxL)
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (TopTx, Tx, extractHash)
import Cardano.Ledger.Keys
    ( VKey (..)
    , WitVKey (..)
    , signedDSIGN
    )
import Cardano.Ledger.TxIn (TxId (..))
import Cardano.Wallet.Tools.Sign (DetachedWitness (..))
import Data.Maybe (mapMaybe)
import Data.Set qualified as Set
import Lens.Micro ((&), (.~))

{- | The verification-key witness of a transaction: the signer's public
key and its signature over the blake2b-256 hash of the body bytes.
-}
detachedWitness
    :: SignKeyDSIGN Ed25519DSIGN
    -> Tx TopTx ConwayEra
    -> DetachedWitness
detachedWitness key tx =
    DetachedWitness
        { detachedWitnessVKey =
            rawSerialiseVerKeyDSIGN (deriveVerKeyDSIGN key)
        , detachedWitnessSignature = rawSerialiseSigDSIGN signature
        }
  where
    TxId bodyHash = txIdTx tx
    SignedDSIGN signature = signedDSIGN key (extractHash bodyHash)

{- | The transaction with exactly the witnesses given as its key
witnesses: those the transaction already carries are replaced, not kept.
The body bytes and the identity are preserved. The witnesses must have
been verified beforehand; bytes that are not a key and a signature add
nothing.
-}
assembleWitnessed
    :: Tx TopTx ConwayEra
    -> [DetachedWitness]
    -> Tx TopTx ConwayEra
assembleWitnessed tx witnesses =
    tx
        & witsTxL . addrTxWitsL .~ Set.fromList (mapMaybe keyWitness witnesses)
  where
    keyWitness (DetachedWitness key signature) = do
        verKey <- rawDeserialiseVerKeyDSIGN key
        sig <- rawDeserialiseSigDSIGN signature
        pure (WitVKey (VKey verKey) (SignedDSIGN sig))
