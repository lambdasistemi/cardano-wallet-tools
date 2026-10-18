{- |
Module      : Cardano.Wallet.Tools.Ledger.Submit
Description : The pure planner that decides how a signed bundle is submitted
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The decisions of a submitting tool, all pure: which witness belongs to
which body (by verifying its signature over that body's identity, never
by its file name), which key hashes each transaction needs a witness
for (its required signers and the payment key hashes of its inputs and
collateral; a script credential adds nothing), and, given where the
chain holds each transaction and the tip, the ordered plan of what to
send and what to skip. Every refusal names what it concerns and no
secret, and is raised before the plan holds any send step. The module
reads no file, no clock and no chain: those belong to the caller.
-}
module Cardano.Wallet.Tools.Ledger.Submit
    ( -- * Chain view
      ChainPoint (..)
    , InclusionStatus (..)

      -- * Plan
    , PlanStep (..)
    , SubmitRefusal (..)
    , renderSubmitRefusal
    , neededKeys
    , matchWitnesses
    , planSubmission
    ) where

import Cardano.Crypto.DSIGN
    ( Ed25519DSIGN
    , SigDSIGN
    , VerKeyDSIGN
    , rawDeserialiseSigDSIGN
    , rawDeserialiseVerKeyDSIGN
    , verifyDSIGN
    )
import Cardano.Crypto.Hash (hashToBytes)
import Cardano.Ledger.Address (Addr (..))
import Cardano.Ledger.Api.Tx (bodyTxL)
import Cardano.Ledger.Api.Tx.Body
    ( collateralInputsTxBodyL
    , inputsTxBodyL
    , reqSignerHashesTxBodyL
    )
import Cardano.Ledger.Api.Tx.Out (TxOut, addrTxOutL)
import Cardano.Ledger.BaseTypes (SlotNo)
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Core (TopTx, Tx, extractHash)
import Cardano.Ledger.Credential (Credential (KeyHashObj))
import Cardano.Ledger.Keys (VKey (..), hashKey, unKeyHash)
import Cardano.Ledger.TxIn (TxId (..), TxIn (..))
import Cardano.Wallet.Tools.Ledger.Bundle
    ( Bundle (..)
    , BundleRefusal (..)
    , BundleTransaction (..)
    , bodyDeadline
    , bodyIdentity
    , checkBundle
    , renderBundleRefusal
    )
import Cardano.Wallet.Tools.Ledger.Envelope
    ( decodeTransactionEnvelope
    , hexText
    )
import Cardano.Wallet.Tools.Sign (DetachedWitness (..))
import Control.Monad (foldM_, forM, forM_, unless)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Word (Word64)
import Lens.Micro ((^.))

-- | A point of the chain: the genesis, or a slot and a block hash.
data ChainPoint = Genesis | At SlotNo ByteString
    deriving stock (Eq, Show)

{- | Where a transaction sits on the chain: found, with the chain point
of the block that carries it and a confirmation count, or not found.
-}
data InclusionStatus
    = -- | the chain point of the block carrying it, and its confirmations
      IncludedAt ChainPoint Word64
    | -- | the chain view does not know the transaction
      NotOnChain
    deriving stock (Eq, Show)

-- | Why submitting a bundle was refused. None names a key or a passphrase.
data SubmitRefusal
    = -- | the bundle itself, refused by its own checks
      SubmitBundleRefused BundleRefusal
    | -- | a witness that verifies against no body of the bundle, carrying
      -- its public key
      SubmitWitnessForeignBody ByteString
    | -- | a witness for a key hash no transaction needs, carrying the key hash
      SubmitWitnessUnneededKey ByteString
    | -- | a key hash a transaction needs and no witness covers, carrying
      -- the key hash and the body's identity
      SubmitWitnessMissing ByteString ByteString
    | -- | a transaction not on the chain whose validity upper bound is at
      -- or before the tip slot, carrying its identity, the bound and the tip
      SubmitBodyExpired ByteString Word64 Word64
    | -- | an input neither produced by an earlier body nor on the chain
      SubmitInputUnresolved TxIn
    deriving stock (Eq, Show)

{- | One step of the plan, in the bundle's order: send the body with
exactly its verified witnesses, or skip a transaction the chain already
holds.
-}
data PlanStep
    = -- | the body to send, its decoded transaction and verified witnesses
      PlanSend BundleTransaction (Tx TopTx ConwayEra) [DetachedWitness]
    | -- | a transaction the chain holds, with its chain point and
      -- confirmations: not sent again
      PlanFound BundleTransaction ChainPoint Word64
    deriving stock (Eq, Show)

-- | One line naming the refusal, carrying what it concerns and no secret.
renderSubmitRefusal :: SubmitRefusal -> String
renderSubmitRefusal = \case
    SubmitBundleRefused refusal -> renderBundleRefusal refusal
    SubmitWitnessForeignBody key ->
        "the witness carrying the public key "
            <> hexText key
            <> " verifies against no transaction of the bundle"
    SubmitWitnessUnneededKey keyHash ->
        "the key hash "
            <> hexText keyHash
            <> " needs no witness: no transaction of the bundle spends \
               \from it or names it as a required signer"
    SubmitWitnessMissing keyHash identity ->
        "the transaction "
            <> hexText identity
            <> " needs a witness for the key hash "
            <> hexText keyHash
            <> " and none was given"
    SubmitBodyExpired identity bound tip ->
        "the transaction "
            <> hexText identity
            <> " is not on the chain and its validity upper bound "
            <> show bound
            <> " is at or before the tip slot "
            <> show tip
            <> ": rebuild the bundle"
    SubmitInputUnresolved reference ->
        "the input "
            <> renderTxIn reference
            <> " is produced by no earlier transaction of the bundle \
               \and is not on the chain"

{- | The key hashes each transaction needs a witness for, by the
transaction's recorded identity: its required signers plus the payment
key hashes of the outputs its inputs and collateral inputs spend. A
script credential adds nothing. An input the resolved outputs do not
hold is refused.
-}
neededKeys
    :: Bundle
    -> Map TxIn (TxOut ConwayEra)
    -> Either SubmitRefusal (Map ByteString (Set ByteString))
neededKeys bundle resolved = do
    entries <- forM (toList (bundleTransactions bundle)) $ \transaction -> do
        body <- decoded transaction
        spent <-
            mapM
                resolvedOutput
                ( Set.toList
                    ( body ^. bodyTxL . inputsTxBodyL
                        <> body ^. bodyTxL . collateralInputsTxBodyL
                    )
                )
        let signers =
                Set.fromList
                    [ hashToBytes (unKeyHash hash)
                    | hash <- toList (body ^. bodyTxL . reqSignerHashesTxBodyL)
                    ]
            payments =
                Set.fromList
                    [ keyHash
                    | out <- spent
                    , Just keyHash <- [paymentKeyHashOf out]
                    ]
        pure (bundleTxIdentity transaction, Set.union signers payments)
    pure (Map.fromList entries)
  where
    resolvedOutput reference =
        maybe
            (Left (SubmitInputUnresolved reference))
            Right
            (Map.lookup reference resolved)
    paymentKeyHashOf out = case out ^. addrTxOutL of
        Addr _ (KeyHashObj hash) _ -> Just (hashToBytes (unKeyHash hash))
        _ -> Nothing

{- | Each witness paired with the body it verifies against, by verifying
its signature over the hash of that body as the ledger computes it, and
keyed by the identity the bundle records for the transaction. A witness
that verifies against no body is refused.
-}
matchWitnesses
    :: Bundle
    -> [DetachedWitness]
    -> Either SubmitRefusal (Map ByteString [DetachedWitness])
matchWitnesses bundle witnesses = do
    signed <- forM (toList (bundleTransactions bundle)) $ \transaction -> do
        body <- decoded transaction
        pure (bundleTxIdentity transaction, bodyIdentity body)
    pairWitnesses signed witnesses

{- | Each witness paired with the one recorded identity whose signed
message it verifies over, or refused when there is none.
-}
pairWitnesses
    :: [(ByteString, ByteString)]
    -- ^ each recorded identity, with the message a witness for it signs
    -> [DetachedWitness]
    -> Either SubmitRefusal (Map ByteString [DetachedWitness])
pairWitnesses signed witnesses = do
    paired <- forM witnesses $ \witness ->
        case [ recorded
             | (recorded, message) <- signed
             , witnessVerifies witness message
             ] of
            [recorded] -> Right (recorded, [witness])
            _ -> Left (SubmitWitnessForeignBody (detachedWitnessVKey witness))
    pure (Map.fromListWith (flip (<>)) paired)

{- | The ordered plan: which transactions to send, with exactly their
verified witnesses, and which the chain already holds. A transaction is
held when the chain view gives it an inclusion point; every other one,
whether the view says it is not on the chain or says nothing, is still
to send and is judged the same way. What is still to send must pass the
bundle's own offline checks, have its inputs resolved, be witnessed for
exactly the keys it needs and not be expired; every refusal is raised
before the plan holds a send step. A held transaction is skipped and
judged for none of that; it is neither decoded nor checked.
-}
planSubmission
    :: Bundle
    -> [DetachedWitness]
    -> Map TxIn (TxOut ConwayEra)
    -> Map ByteString InclusionStatus
    -> Word64
    -> Either SubmitRefusal (NonEmpty PlanStep)
planSubmission bundle witnesses resolved statuses tip = do
    let transactions = toList (bundleTransactions bundle)
        held transaction =
            case Map.lookup (bundleTxIdentity transaction) statuses of
                Just IncludedAt{} -> True
                _ -> False
        sending = filter (not . held) transactions
    -- the offline checks, on what is still to send: its recorded
    -- identities are then its bodies' hashes, which the chain view is
    -- looked up by and the witnesses are verified against
    sendingBundle <- case sending of
        [] -> Right Nothing
        first' : more -> do
            let toSend = bundle{bundleTransactions = first' :| more}
            first SubmitBundleRefused (checkBundle toSend)
            Right (Just toSend)
    -- a witness belongs to the transaction whose identity it signed; a
    -- held transaction's identity is the one the chain view gave
    paired <-
        pairWitnesses
            [ (identity, identity) | t <- transactions, let identity = bundleTxIdentity t
            ]
            witnesses
    -- only a transaction still to send needs its keys witnessed: one the
    -- chain holds is skipped, and the inputs it spent are no longer on
    -- the chain to resolve; a witness paired with it is not used
    needed <-
        maybe (Right Map.empty) (`neededKeys` resolved) sendingBundle
    -- every witness is for a key its transaction needs, and no key is
    -- witnessed twice: a second witness for a covered key is unneeded,
    -- whoever signed it; this comes before the missing check, so a lone
    -- stranger's witness is refused as unneeded, not as an incomplete set
    forM_ (Map.toList (Map.restrictKeys paired (Map.keysSet needed))) $
        \(identity, ws) ->
            foldM_
                ( \covered witness ->
                    let keyHash = witnessKeyHash witness
                    in  if keyHash `Set.member` Map.findWithDefault Set.empty identity needed
                            && not (keyHash `Set.member` covered)
                            then Right (Set.insert keyHash covered)
                            else Left (SubmitWitnessUnneededKey keyHash)
                )
                Set.empty
                ws
    -- every key a transaction needs has a verified witness
    forM_ (Map.toList needed) $ \(identity, keys) ->
        forM_ (Set.toList keys) $ \keyHash ->
            unless
                ( any
                    ((== keyHash) . witnessKeyHash)
                    (Map.findWithDefault [] identity paired)
                )
                (Left (SubmitWitnessMissing keyHash identity))
    -- an expired body: still to send and the tip at or past its
    -- exclusive upper bound
    forM_ sending $ \transaction -> do
        body <- decoded transaction
        case bodyDeadline body of
            Just bound
                | tip >= bound ->
                    Left (SubmitBodyExpired (bundleTxIdentity transaction) bound tip)
            _ -> pure ()
    steps <- forM transactions $ \transaction ->
        case Map.lookup (bundleTxIdentity transaction) statuses of
            Just (IncludedAt point confirmations) ->
                Right (PlanFound transaction point confirmations)
            _ -> do
                body <- decoded transaction
                Right
                    ( PlanSend
                        transaction
                        body
                        (Map.findWithDefault [] (bundleTxIdentity transaction) paired)
                    )
    case steps of
        [] -> Left (SubmitBundleRefused (BundleField "transactions" "is empty"))
        firstStep : restSteps -> Right (firstStep :| restSteps)

-- | The decoded transaction of a bundle entry, or the bundle refusal.
decoded
    :: BundleTransaction -> Either SubmitRefusal (Tx TopTx ConwayEra)
decoded transaction =
    first
        ( const
            ( SubmitBundleRefused
                (BundleEnvelopeUndecodable (hexText (bundleTxIdentity transaction)))
            )
        )
        (decodeTransactionEnvelope (bundleTxEnvelope transaction))

{- | The payment key hash a detached witness's key carries, derived
through the ledger's own key hashing so it is the hash an address names.
-}
witnessKeyHash :: DetachedWitness -> ByteString
witnessKeyHash witness =
    case rawDeserialiseVerKeyDSIGN (detachedWitnessVKey witness) of
        Just verKey -> hashToBytes (unKeyHash (hashKey (VKey verKey)))
        Nothing -> ""

-- | Whether a detached witness's signature verifies over a body hash.
witnessVerifies :: DetachedWitness -> ByteString -> Bool
witnessVerifies witness identity =
    case ( rawDeserialiseVerKeyDSIGN (detachedWitnessVKey witness)
            :: Maybe (VerKeyDSIGN Ed25519DSIGN)
         , rawDeserialiseSigDSIGN (detachedWitnessSignature witness)
            :: Maybe (SigDSIGN Ed25519DSIGN)
         ) of
        (Just verKey, Just sig) ->
            verifyDSIGN () verKey identity sig == Right ()
        _ -> False

{- | An output reference as a refusal spells it: the identity in hex, a
@#@, the index.
-}
renderTxIn :: TxIn -> String
renderTxIn (TxIn (TxId h) index) =
    hexText (hashToBytes (extractHash h)) <> "#" <> show index
