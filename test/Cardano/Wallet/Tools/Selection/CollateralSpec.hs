{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Cardano.Wallet.Tools.Selection.CollateralSpec
Description : Tests for greedy collateral selection.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0
-}
module Cardano.Wallet.Tools.Selection.CollateralSpec
    ( spec
    ) where

import Test.Hspec
import Test.QuickCheck

import Cardano.Wallet.Tools.Selection.Collateral

spec :: Spec
spec = describe "selectCollateral" $ do
    it "needs no collateral for a non-positive requirement" $
        selectCollateral
            (CollateralRequest 0 3 False)
            [Candidate 'a' 5 False]
            `shouldBe` Right (CollateralChoice [] 0)

    it "covers the target largest-first in the fewest inputs" $
        selectCollateral
            (CollateralRequest 10 3 False)
            [ Candidate 'a' 4 False
            , Candidate 'b' 7 False
            , Candidate 'c' 4 False
            ]
            `shouldBe` Right
                ( CollateralChoice
                    [Candidate 'b' 7 False, Candidate 'a' 4 False]
                    11
                )

    it "excludes token UTxOs unless allowed" $
        selectCollateral
            (CollateralRequest 5 3 False)
            [Candidate 'a' 9 True]
            `shouldBe` Left NoEligibleCandidates

    it "uses token UTxOs when allowed" $
        selectCollateral
            (CollateralRequest 5 3 True)
            [Candidate 'a' 9 True]
            `shouldBe` Right (CollateralChoice [Candidate 'a' 9 True] 9)

    it "reports a shortfall capped at maxInputs" $
        selectCollateral
            (CollateralRequest 100 2 False)
            [ Candidate 'a' 10 False
            , Candidate 'b' 9 False
            , Candidate 'c' 8 False
            ]
            `shouldBe` Left
                ( CollateralShortfall
                    [Candidate 'a' 10 False, Candidate 'b' 9 False]
                    19
                    100
                )

    it "a covering result meets the target within the cap" $
        property prop_coversWithinCap

prop_coversWithinCap
    :: Positive Integer
    -> Positive Int
    -> [(Positive Integer, Bool)]
    -> Bool
prop_coversWithinCap (Positive req) (Positive cap) raw =
    let candidates =
            [ Candidate i l a
            | (i, (Positive l, a)) <- zip [0 :: Int ..] raw
            ]
        request = CollateralRequest req cap True
    in  case selectCollateral request candidates of
            Right (CollateralChoice ins s) ->
                s >= req && length ins <= cap
            Left (CollateralShortfall sel s _) ->
                s < req && length sel <= cap
            Left NoEligibleCandidates -> null candidates
