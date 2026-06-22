{- |
Module      : Cardano.Wallet.Tools.Selection.Collateral
Description : Pure multi-UTxO collateral selection.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Greedy, largest-first collateral selection to a required total,
capped at @maxCollateralInputs@. This is the pure heart of the
toolkit: the ledger-typed wrappers feed it resolved wallet UTxOs and
a required amount (@ceil(fee * collateralPercentage \/ 100)@), and it
returns either a covering set or an explicit shortfall.

The function never silently under-provisions: when the eligible
candidates (capped at the protocol limit) cannot reach the target it
returns 'CollateralShortfall' carrying what it managed to gather, so
callers can tell the operator exactly how far short they are.
-}
module Cardano.Wallet.Tools.Selection.Collateral
    ( -- * Inputs
      Candidate (..)
    , CollateralRequest (..)

      -- * Outputs
    , CollateralChoice (..)
    , CollateralError (..)

      -- * Selection
    , selectCollateral
    ) where

import Data.List (sortBy)
import Data.Ord (Down (..), comparing)

{- | A wallet UTxO offered as a collateral candidate, parameterized over
the reference type so the pure core stays free of ledger types.
-}
data Candidate ref = Candidate
    { candRef :: !ref
    -- ^ Opaque reference (a @TxIn@ in the ledger-typed layer).
    , candLovelace :: !Integer
    -- ^ ADA the candidate contributes to collateral.
    , candHasAssets :: !Bool
    -- ^ Whether the candidate carries native assets. Token-bearing
    --     candidates are only eligible when
    --     'crAllowAssets' is set (a conserving @collateral_return@ is
    --     then the caller's responsibility).
    }
    deriving stock (Eq, Show)

-- | What the collateral set must satisfy.
data CollateralRequest = CollateralRequest
    { crRequiredLovelace :: !Integer
    -- ^ @ceil(fee * collateralPercentage \/ 100)@.
    , crMaxInputs :: !Int
    -- ^ Protocol @maxCollateralInputs@ cap.
    , crAllowAssets :: !Bool
    -- ^ Whether token-bearing candidates may be used.
    }
    deriving stock (Eq, Show)

-- | A covering collateral selection.
data CollateralChoice ref = CollateralChoice
    { ccInputs :: ![Candidate ref]
    -- ^ Chosen candidates, largest-first.
    , ccSelectedLovelace :: !Integer
    -- ^ Their cumulative lovelace (>= 'crRequiredLovelace').
    }
    deriving stock (Eq, Show)

-- | Why a collateral set could not be assembled.
data CollateralError ref
    = -- | The eligible candidates, capped at 'crMaxInputs', cannot
      -- reach the required total. Carries the best partial set, its
      -- cumulative lovelace, and the required lovelace.
      CollateralShortfall
        ![Candidate ref]
        !Integer
        !Integer
    | -- | No candidate is eligible (all carry assets while
      -- 'crAllowAssets' is unset, or the pool was empty).
      NoEligibleCandidates
    deriving stock (Eq, Show)

{- | Select a collateral set covering 'crRequiredLovelace'.

Largest-first so the target is reached in the fewest inputs (the
@maxCollateralInputs@ cap makes input count the binding constraint).
A non-positive requirement needs no collateral and yields the empty
selection.
-}
selectCollateral
    :: CollateralRequest
    -> [Candidate ref]
    -> Either (CollateralError ref) (CollateralChoice ref)
selectCollateral req candidates
    | crRequiredLovelace req <= 0 =
        Right (CollateralChoice [] 0)
    | null eligible =
        Left NoEligibleCandidates
    | otherwise = go 0 [] (take (crMaxInputs req) sorted)
  where
    eligible =
        filter
            (\c -> crAllowAssets req || not (candHasAssets c))
            candidates
    sorted = sortBy (comparing (Down . candLovelace)) eligible

    go !acc picked rest
        | acc >= crRequiredLovelace req =
            Right
                ( CollateralChoice
                    { ccInputs = reverse picked
                    , ccSelectedLovelace = acc
                    }
                )
        | (c : cs) <- rest =
            go (acc + candLovelace c) (c : picked) cs
        | otherwise =
            Left
                ( CollateralShortfall
                    (reverse picked)
                    acc
                    (crRequiredLovelace req)
                )
