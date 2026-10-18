{- |
Module      : Support.LedgerScenario
Description : Generated faulty bundles and the refusals they must raise
License     : Apache-2.0

A scenario is a short list of slots. Each slot records one transaction
of a bundle, drawn from a pool of three bodies that differ in what a
check can find in them, with a choice of faults to write into the
record: a flipped identity, a wrong deadline, an envelope that is not a
transaction. Two slots drawing the same body unflipped record the same
identity. The refusals a bundle of slots must raise are worked out here
from the choices alone, never by calling the library under test.
-}
module Support.LedgerScenario
    ( Slot (..)
    , genSlots
    , scenarioBundle
    , scenarioRefusals
    , scenarioFailedChecks
    ) where

import Cardano.Crypto.Hash (hashToBytes)
import Cardano.Ledger.Keys (unKeyHash)
import Cardano.Wallet.Tools.Ledger.Bundle
import Cardano.Wallet.Tools.Ledger.Envelope (TextEnvelope (..))
import Data.ByteString (ByteString)
import Data.List (nub)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Set qualified as Set
import Data.Word (Word64)
import Support.Ledger
import Test.QuickCheck (Gen, chooseInt, elements, vectorOf)

-- | One transaction record: which body, and which faults it carries.
data Slot = Slot
    { slotBody :: Int
    -- ^ index into the pool of three bodies
    , slotFlipIdentity :: Bool
    , slotWrongDeadline :: Bool
    , slotBadEnvelope :: Bool
    }
    deriving stock (Eq, Show)

{- | The pool: a bounded body requiring nothing, a bounded body
requiring a key no signer covers, an unbounded body requiring the key
the signer covers.
-}
pool :: [ConwayTx]
pool =
    [ txOf (syntheticBody 1000)
    , txOf
        ( syntheticBodyRequiring
            1001
            (Set.singleton (requiredHashOf strangerKey))
        )
    , txOf
        ( syntheticBodyRequiring 1002 (Set.singleton (requiredHashOf fixedKey))
        )
    ]

bodyOf :: Slot -> ConwayTx
bodyOf slot = pool !! slotBody slot

-- | Between one and five slots, any body, any faults.
genSlots :: Gen [Slot]
genSlots = do
    n <- chooseInt (1, 5)
    vectorOf n genSlot

genSlot :: Gen Slot
genSlot =
    Slot
        <$> chooseInt (0, length pool - 1)
        <*> elements [False, False, True]
        <*> elements [False, False, True]
        <*> elements [False, False, False, True]

recordedIdentity :: Slot -> ByteString
recordedIdentity slot
    | slotFlipIdentity slot = flippedIdentity (identityOf (bodyOf slot))
    | otherwise = identityOf (bodyOf slot)

recordedDeadline :: Slot -> Maybe Word64
recordedDeadline slot
    | slotWrongDeadline slot = Just (maybe 7 (+ 1) actual)
    | otherwise = actual
  where
    actual = deadlineOfTx (bodyOf slot)

-- | The bundle the slots record, signed for by the fixed key alone.
scenarioBundle :: [Slot] -> Bundle
scenarioBundle slots =
    sampleBundle
        { bundleTransactions = case map record slots of
            [] -> error "Support.LedgerScenario: no slots"
            t : ts -> t :| ts
        }
  where
    record slot =
        (bundleTxOf (bodyOf slot) [])
            { bundleTxIdentity = recordedIdentity slot
            , bundleTxDeadline = recordedDeadline slot
            , bundleTxEnvelope =
                if slotBadEnvelope slot
                    then (envelopeOfTx (bodyOf slot)){envelopeCborHex = "ff00"}
                    else envelopeOfTx (bodyOf slot)
            }

{- | The refusals the bundle of these slots must raise, in the order of
the checks: envelopes, identities, deadlines, distinct identities,
signer coverage; within a check, in slot order.
-}
scenarioRefusals :: [Slot] -> [BundleRefusal]
scenarioRefusals slots =
    undecodable ++ identities ++ deadlines ++ duplicates ++ signers
  where
    decodable = filter (not . slotBadEnvelope) slots
    undecodable =
        [ BundleEnvelopeUndecodable (hexOf (recordedIdentity s))
        | s <- slots
        , slotBadEnvelope s
        ]
    identities =
        [ BundleIdentityMismatch
            (recordedIdentity s)
            (identityOf (bodyOf s))
        | s <- decodable
        , slotFlipIdentity s
        ]
    deadlines =
        [ BundleDeadlineMismatch
            (recordedDeadline s)
            (deadlineOfTx (bodyOf s))
            (recordedIdentity s)
        | s <- decodable
        , slotWrongDeadline s
        ]
    ids = map recordedIdentity slots
    duplicates =
        [ BundleDuplicateIdentity i
        | i <- nub [i | (k, i) <- zip [0 :: Int ..] ids, i `elem` take k ids]
        ]
    signers =
        [ BundleSignerNotCovered
            (hashToBytes (unKeyHash h))
            (recordedIdentity s)
        | s <- decodable
        , h <- Set.toAscList (requiredOf (bodyOf s))
        , hashToBytes (unKeyHash h) /= keyHashBytes fixedKey
        ]

{- | The names of the checks the slots fail, in the order of the
refusals.
-}
scenarioFailedChecks :: [Slot] -> [String]
scenarioFailedChecks = map checkOf . scenarioRefusals
  where
    checkOf = \case
        BundleEnvelopeUndecodable{} -> "envelope"
        BundleIdentityMismatch{} -> "identity"
        BundleDeadlineMismatch{} -> "deadline"
        BundleDuplicateIdentity{} -> "distinct-identities"
        BundleSignerNotCovered{} -> "signers"
        other -> error ("not a scenario refusal: " <> show other)
