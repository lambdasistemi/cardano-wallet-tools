{- |
Module      : Cardano.Wallet.Tools.Selection.Strategy
Description : Pluggable pure coin-selection strategies.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Input selection to cover a lovelace target, with a pluggable
'Strategy'. 'LargestFirst' is the default — fewest inputs, the same
reasoning that governs collateral. 'RandomImprove' is a seeded,
deterministic ordering (a privacy-flavoured alternative); the seed
keeps it reproducible under GHC-WASM/GHC-JS where ambient randomness
is unavailable.

This is the pure skeleton: a covering selection or an explicit
'InsufficientFunds'. The ledger-typed layer feeds it resolved UTxOs
and reads the chosen refs back into the build.
-}
module Cardano.Wallet.Tools.Selection.Strategy
    ( -- * Strategy
      Strategy (..)

      -- * Inputs
    , InputCandidate (..)

      -- * Outputs
    , SelectionError (..)

      -- * Selection
    , selectInputs
    ) where

import Data.List (sortBy)
import Data.Ord (Down (..), comparing)
import Data.Word (Word64)

-- | How inputs are ordered before greedy accumulation.
data Strategy
    = -- | Largest lovelace first; fewest inputs.
      LargestFirst
    | -- | Seeded deterministic ordering (reproducible coin selection).
      RandomImprove !Word64
    deriving stock (Eq, Show)

{- | A wallet UTxO offered as a funding input. Parameterized over the
reference type so the pure core stays free of ledger types.
-}
data InputCandidate ref = InputCandidate
    { icRef :: !ref
    -- ^ Opaque reference (a @TxIn@ in the ledger-typed layer).
    , icLovelace :: !Integer
    -- ^ ADA the input contributes.
    }
    deriving stock (Eq, Show)

-- | Selection could not cover the target.
newtype SelectionError = InsufficientFunds (Integer, Integer)
    deriving stock (Eq, Show)

{- | Select inputs whose cumulative lovelace covers @target@, ordered by
the given 'Strategy'. A non-positive target needs no inputs.
-}
selectInputs
    :: Strategy
    -> Integer
    -> [InputCandidate ref]
    -> Either SelectionError [InputCandidate ref]
selectInputs strategy target candidates
    | target <= 0 = Right []
    | otherwise = accumulate (ordered strategy candidates)
  where
    available = sum (map icLovelace candidates)

    accumulate = go 0 []
      where
        go !acc picked rest
            | acc >= target = Right (reverse picked)
            | (c : cs) <- rest =
                go (acc + icLovelace c) (c : picked) cs
            | otherwise =
                Left (InsufficientFunds (available, target))

-- | Order candidates according to the strategy.
ordered :: Strategy -> [InputCandidate ref] -> [InputCandidate ref]
ordered LargestFirst =
    sortBy (comparing (Down . icLovelace))
ordered (RandomImprove seed) =
    map snd
        . sortBy (comparing fst)
        . zip (lcgStream seed)

{- | A deterministic pseudo-random key stream from a 64-bit seed
(Knuth's MMIX LCG constants). Pure and portable — no system RNG.
-}
lcgStream :: Word64 -> [Word64]
lcgStream = iterate step
  where
    step s = s * 6364136223846793005 + 1442695040888963407
