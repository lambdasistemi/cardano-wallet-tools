{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Cardano.Wallet.Tools.Selection.StrategySpec
Description : Tests for pluggable coin-selection strategies.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0
-}
module Cardano.Wallet.Tools.Selection.StrategySpec
    ( spec
    ) where

import Data.List (sort)
import Data.Word (Word64)
import Test.Hspec
import Test.QuickCheck

import Cardano.Wallet.Tools.Selection.Strategy

spec :: Spec
spec = describe "selectInputs" $ do
    it "needs no inputs for a non-positive target" $
        selectInputs LargestFirst 0 [InputCandidate 'a' 5]
            `shouldBe` Right []

    it "LargestFirst covers the target in the fewest inputs" $
        selectInputs
            LargestFirst
            10
            [ InputCandidate 'a' 4
            , InputCandidate 'b' 7
            , InputCandidate 'c' 4
            ]
            `shouldBe` Right
                [InputCandidate 'b' 7, InputCandidate 'a' 4]

    it "reports insufficient funds" $
        selectInputs
            LargestFirst
            100
            [InputCandidate 'a' 10, InputCandidate 'b' 9]
            `shouldBe` Left (InsufficientFunds (19, 100))

    it "RandomImprove still covers the target" $
        property prop_randomCovers

    it "every strategy picks only real candidates" $
        property prop_picksSubset

prop_randomCovers
    :: Word64 -> Positive Integer -> [Positive Integer] -> Bool
prop_randomCovers seed (Positive target) raw =
    let cs = candidatesFrom raw
        available = sum (map icLovelace cs)
    in  case selectInputs (RandomImprove seed) target cs of
            Right picked ->
                sum (map icLovelace picked) >= target
            Left (InsufficientFunds (a, t)) ->
                a == available && a < target && t == target

prop_picksSubset
    :: Bool -> Integer -> [Positive Integer] -> Bool
prop_picksSubset useRandom target raw =
    let cs = candidatesFrom raw
        strategy = if useRandom then RandomImprove 42 else LargestFirst
    in  case selectInputs strategy target cs of
            Right picked ->
                sort (map icRef picked) `isSubsetOf` sort (map icRef cs)
            Left _ -> True
  where
    isSubsetOf xs ys = all (`elem` ys) xs

candidatesFrom :: [Positive Integer] -> [InputCandidate Int]
candidatesFrom raw =
    [InputCandidate i l | (i, Positive l) <- zip [0 :: Int ..] raw]
