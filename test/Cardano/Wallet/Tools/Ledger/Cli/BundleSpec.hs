{- |
Module      : Cardano.Wallet.Tools.Ledger.Cli.BundleSpec
Description : @cwt bundle check@ as the operator runs it
License     : Apache-2.0

The command is run as a process, the way an operator runs it, and its
exit status and its two output streams are what is observed: success
exits 0 and prints only a summary, a failure exits non-zero and prints
one line per failed check, naming it, and a file that cannot be read or
decoded exits non-zero naming why. The bundles that fail are generated,
several checks at once, and the lines expected are worked out from the
faults that were written, never from the command.
-}
module Cardano.Wallet.Tools.Ledger.Cli.BundleSpec (spec) where

import Cardano.Wallet.Tools.Ledger.Bundle
import Cardano.Wallet.Tools.Ledger.Envelope (TextEnvelope (..))
import Control.Exception (bracket)
import Data.Aeson (Value (Number))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List (isInfixOf, isPrefixOf)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Support.Ledger
import Support.LedgerScenario
import System.Directory
    ( findExecutable
    , getTemporaryDirectory
    , removeFile
    )
import System.Exit (ExitCode (..))
import System.IO (hClose, openBinaryTempFile)
import System.Process (readProcessWithExitCode)
import Test.Hspec
import Test.QuickCheck
    ( Property
    , counterexample
    , forAll
    , ioProperty
    , property
    , withMaxSuccess
    )

spec :: Spec
spec = describe "cwt bundle check" $ do
    whenAllChecksPass
    whenChecksFail
    whenTheFileIsNotABundle
    theCommandLine

-- | What a run of the command left: exit status and both streams.
data Run = Run
    { runExit :: ExitCode
    , runOut :: String
    , runErr :: String
    }
    deriving stock (Show)

-- | The command the operator runs, from the search path of the specs.
cwt :: [String] -> IO Run
cwt args = do
    found <- findExecutable "cwt"
    exe <- case found of
        Just path -> pure path
        Nothing ->
            fail
                "cwt is not on the search path of the specs, so the command it runs cannot be observed"
    (code, out, err) <- readProcessWithExitCode exe args ""
    pure (Run code out err)

-- | Run the command on a file holding the bytes given.
checkingBytes :: ByteString -> IO Run
checkingBytes bytes =
    bracket
        ( getTemporaryDirectory
            >>= \directory -> openBinaryTempFile directory "bundle-check.json"
        )
        (removeFile . fst)
        ( \(path, handle) -> do
            BS.hPut handle bytes
            hClose handle
            cwt ["bundle", "check", path]
        )

failed :: Run -> Bool
failed run = runExit run /= ExitSuccess

-- * Every check passes

whenAllChecksPass :: Spec
whenAllChecksPass = describe "when every check passes" $ do
    it "exits 0 and prints only the summary of the bundle" $ do
        run <- checkingBytes (encodeBundle sampleBundle)
        runExit run `shouldBe` ExitSuccess
        lines (runOut run) `shouldBe` [summaryOf sampleBundle]
        runErr run `shouldBe` ""
    it "passes the bundle another tool wrote, unchanged" $ do
        committed <- readBundleFixture "unsigned-bundle.json"
        run <- checkingBytes committed
        runExit run `shouldBe` ExitSuccess
        lines (runOut run) `shouldBe` [summaryOf fixtureBundle]
        runErr run `shouldBe` ""
    it "reads the file it is given, not another one" $ do
        let single = sampleBundle{bundleTransactions = oneOf sampleBundle}
        run <- checkingBytes (encodeBundle single)
        lines (runOut run) `shouldBe` [summaryOf single]
        summaryOf single `shouldNotBe` summaryOf sampleBundle

oneOf :: Bundle -> NonEmpty BundleTransaction
oneOf bundle = case bundleTransactions bundle of
    t :| _ -> t :| []

-- | The summary line, from the bundle's own fields.
summaryOf :: Bundle -> String
summaryOf bundle =
    "ok: transactions="
        <> show (length (bundleTransactions bundle))
        <> " signers="
        <> show (length (bundleSigners bundle))
        <> " networkMagic="
        <> show (bundleNetworkMagic bundle)

-- * A check fails

whenChecksFail :: Spec
whenChecksFail = describe "when checks fail" $ do
    it "exits non-zero and names the one failed check" $ do
        let tampered =
                withFirst
                    (\t -> t{bundleTxIdentity = flippedIdentity (bundleTxIdentity t)})
        run <- checkingBytes (encodeBundle tampered)
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        map (takeWhile (/= ':')) (lines (runErr run)) `shouldBe` ["identity"]
    it "names every check that failed at once, one line each" $ do
        let slots = [Slot 0 True True False, Slot 1 False False False]
        run <- checkingBytes (encodeBundle (scenarioBundle slots))
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        map (takeWhile (/= ':')) (lines (runErr run))
            `shouldBe` scenarioFailedChecks slots
        scenarioFailedChecks slots
            `shouldBe` ["identity", "deadline", "signers"]
    it
        "names a duplicated identity and an undecodable envelope as their own checks"
        $ do
            let slots =
                    [ Slot 0 False False False
                    , Slot 0 False False False
                    , Slot 2 False False True
                    ]
            run <- checkingBytes (encodeBundle (scenarioBundle slots))
            failed run `shouldBe` True
            map (takeWhile (/= ':')) (lines (runErr run))
                `shouldBe` ["envelope", "distinct-identities"]
    it "prints one line per failed check for any generated bundle" $
        property $
            withMaxSuccess 25 propertyForGenerated

propertyForGenerated :: Property
propertyForGenerated = forAll genSlots $ \slots ->
    ioProperty $ do
        run <- checkingBytes (encodeBundle (scenarioBundle slots))
        let expected = scenarioFailedChecks slots
            named = map (takeWhile (/= ':')) (lines (runErr run))
            ok
                | null expected =
                    runExit run == ExitSuccess
                        && runErr run == ""
                        && lines (runOut run) == [summaryOf (scenarioBundle slots)]
                | otherwise =
                    failed run && runOut run == "" && named == expected
        pure (counterexample (show (slots, run)) ok)

-- * The file is not a bundle

whenTheFileIsNotABundle :: Spec
whenTheFileIsNotABundle = describe "when the file is not a bundle" $ do
    it "exits non-zero naming the file it cannot read" $ do
        let missing = "no-such-bundle-for-the-check.json"
        run <- cwt ["bundle", "check", missing]
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        length (lines (runErr run)) `shouldBe` 1
        runErr run `shouldSatisfy` isInfixOf missing
        runErr run `shouldSatisfy` isInfixOf "cannot read"
    it "exits non-zero naming why bytes that are not JSON do not decode" $ do
        run <- checkingBytes "not json at all"
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        map (takeWhile (/= ':')) (lines (runErr run)) `shouldBe` ["field"]
        runErr run `shouldSatisfy` isInfixOf "not JSON"
    it "exits non-zero naming the version of a bundle it does not read" $ do
        let other =
                tamperJson
                    (KeyMap.insert "version" (Number 2))
                    (encodeBundle sampleBundle)
        run <- checkingBytes other
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        map (takeWhile (/= ':')) (lines (runErr run)) `shouldBe` ["version"]
    it
        "exits non-zero naming the envelope type of a transaction it does not read"
        $ do
            let wrongType =
                    withFirst
                        ( \t ->
                            t
                                { bundleTxEnvelope =
                                    (bundleTxEnvelope t)
                                        { envelopeType = "Witnessed Tx ConwayEra"
                                        }
                                }
                        )
            run <- checkingBytes (encodeBundle wrongType)
            failed run `shouldBe` True
            runOut run `shouldBe` ""
            map (takeWhile (/= ':')) (lines (runErr run))
                `shouldBe` ["envelope-type"]

-- * The command line

theCommandLine :: Spec
theCommandLine = describe "the command line" $ do
    it "needs a file" $ do
        run <- cwt ["bundle", "check"]
        failed run `shouldBe` True
        runOut run `shouldBe` ""
        runErr run `shouldSatisfy` isInfixOf "FILE"
    it "is listed among the commands of cwt" $ do
        run <- cwt ["--help"]
        runExit run `shouldBe` ExitSuccess
        lines (runOut run) `shouldSatisfy` any (isInfixOf "bundle")
    it "describes its subcommand" $ do
        run <- cwt ["bundle", "--help"]
        runExit run `shouldBe` ExitSuccess
        lines (runOut run) `shouldSatisfy` any ("  check" `isPrefixOf`)
