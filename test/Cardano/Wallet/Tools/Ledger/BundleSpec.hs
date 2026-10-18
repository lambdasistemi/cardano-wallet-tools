{- |
Module      : Cardano.Wallet.Tools.Ledger.BundleSpec
Description : The bundle of unsigned transactions: codec and offline checks
License     : Apache-2.0

One row per promise the bundle makes to the offline signer who reads
it:

* what the codec writes, it reads back, the same transactions in the
  same order, and an unknown version, a missing field or a malformed
  envelope is refused by name;
* the offline checks prove every recorded identity against the hash of
  its decoded body and every recorded deadline against the body's
  validity upper bound, name both sides of each disagreement, refuse
  duplicate identities, and require every key hash a body names to be
  covered by a signer address;
* one function reports every failed check, and the other the first;
* the identity the checks compare against is the hash any Cardano tool
  would compute: the transaction id equals an independent blake2b-256
  of the body bytes;
* a bundle written by another tool, committed as a fixture, reads and
  passes unchanged.

Every expected value is obtained at run time from a producer: the
identities from the ledger's transaction id, the addresses from the
ledger's address serialisation, the faults' refusals from the choices
that built them.
-}
module Cardano.Wallet.Tools.Ledger.BundleSpec (spec) where

import Cardano.Ledger.Api.Tx.Body
    ( ValidityInterval (..)
    , mkBasicTxBody
    , vldtTxBodyL
    )
import Cardano.Ledger.BaseTypes (StrictMaybe (SNothing))
import Cardano.Wallet.Tools.Ledger.Bundle
import Cardano.Wallet.Tools.Ledger.Envelope
    ( TextEnvelope (..)
    , acceptedTransactionEnvelopeTypes
    )
import Control.Monad (unless)
import Data.Aeson (Value (..), eitherDecodeStrict)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Char (toLower)
import Data.List (isInfixOf, isPrefixOf, nub, sort)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.List.NonEmpty qualified as NE
import Data.Set qualified as Set
import Data.Vector qualified as V
import Lens.Micro ((&), (.~))
import Support.Ledger
import Support.LedgerScenario
import Test.Hspec
import Test.QuickCheck
    ( Property
    , checkCoverage
    , cover
    , forAll
    , property
    , (===)
    )

spec :: Spec
spec = describe "the bundle of unsigned transactions" $ do
    theCodec
    theSchema
    theOfflineChecks
    everyFailureIsReported
    theIdentityIsTheBodyHash
    theOfficialEnvelope
    theCommittedFixture
    theDocumentedExample

-- * Tampering with the codec's own JSON

-- | A change to the first transaction object of the bundle's JSON.
onFirstTransaction
    :: (KeyMap Value -> KeyMap Value) -> KeyMap Value -> KeyMap Value
onFirstTransaction change top = case KeyMap.lookup "transactions" top of
    Just (Array txs)
        | (Object t) <- V.head txs ->
            KeyMap.insert
                "transactions"
                (Array (V.cons (Object (change t)) (V.tail txs)))
                top
    other -> error ("Bundle spec: no transactions: " <> show other)

sampleBytes :: ByteString
sampleBytes = encodeBundle sampleBundle

renderedBy :: ByteString -> String
renderedBy bytes = case decodeBundle bytes of
    Left refusal -> renderBundleRefusal refusal
    Right _ -> "accepted"

-- | The needle's words all appear in the haystack, in any case.
mentions :: String -> String -> Bool
mentions line needle =
    all
        (\w -> map toLower w `isInfixOf` map toLower line)
        (words needle)

shouldMention :: String -> String -> Expectation
shouldMention line needle =
    unless (line `mentions` needle) $
        expectationFailure
            ("the refusal does not say it: " <> show (needle, line))

-- * The codec

theCodec :: Spec
theCodec = describe "the codec" $ do
    it "round-trips what it writes, transactions in order" $ do
        decoded <- case decodeBundle sampleBytes of
            Right bundle -> pure bundle
            Left refusal ->
                fail ("the round trip refused: " <> renderBundleRefusal refusal)
        fmap bundleTxIdentity (bundleTransactions decoded)
            `shouldBe` fmap bundleTxIdentity (bundleTransactions sampleBundle)
        fmap bundleTxDeadline (bundleTransactions decoded)
            `shouldBe` fmap bundleTxDeadline (bundleTransactions sampleBundle)
        decoded `shouldBe` sampleBundle
    it "round-trips every generated bundle, faulty ones included" $
        property $
            forAll genSlots $ \slots ->
                let bundle = scenarioBundle slots
                in  decodeBundle (encodeBundle bundle) === Right bundle
    it "writes the same bytes for the same bundle" $
        encodeBundle sampleBundle `shouldBe` encodeBundle sampleBundle
    it "refuses an unknown version by name" $ do
        let tampered = tamperJson (KeyMap.insert "version" (Number 2)) sampleBytes
        decodeBundle tampered `shouldBe` Left (BundleUnknownVersion 2)
        renderedBy tampered `shouldMention` "version"
    it "refuses a missing field by name" $ do
        let tampered = tamperJson (KeyMap.delete "networkMagic") sampleBytes
        case decodeBundle tampered of
            Left (BundleField "networkMagic" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
        renderedBy tampered `shouldMention` "networkMagic"
    it "refuses a malformed field by name" $ do
        let tampered =
                tamperJson
                    (KeyMap.insert "networkMagic" (String "not-a-number"))
                    sampleBytes
        case decodeBundle tampered of
            Left (BundleField "networkMagic" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses an envelope of the wrong type by name" $ do
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
        decodeBundle (encodeBundle wrongType)
            `shouldBe` Left (BundleEnvelopeWrongType "Witnessed Tx ConwayEra")
    it "accepts either label the envelope types allow" $
        mapM_
            ( \label ->
                let relabelled =
                        withFirst
                            ( \t ->
                                t
                                    { bundleTxEnvelope =
                                        (bundleTxEnvelope t)
                                            { envelopeType = label
                                            }
                                    }
                            )
                in  fmap
                        (envelopeType . bundleTxEnvelope . NE.head . bundleTransactions)
                        (decodeBundle (encodeBundle relabelled))
                        `shouldBe` Right label
            )
            acceptedTransactionEnvelopeTypes
    it "refuses a signer that is not an address" $ do
        let badSigners = sampleBundle{bundleSigners = "not-an-address" :| []}
        case decodeBundle (encodeBundle badSigners) of
            Left (BundleField "signers" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses an empty signers list" $ do
        let tampered = tamperJson (KeyMap.insert "signers" (Array mempty)) sampleBytes
        case decodeBundle tampered of
            Left (BundleField "signers" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses an empty transaction list" $ do
        let tampered =
                tamperJson (KeyMap.insert "transactions" (Array mempty)) sampleBytes
        case decodeBundle tampered of
            Left (BundleField "transactions" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses an identity that is not 64 hex digits" $ do
        let tampered =
                tamperJson
                    (onFirstTransaction (KeyMap.insert "identity" (String "not-hex")))
                    sampleBytes
        case decodeBundle tampered of
            Left (BundleField "identity" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses an effect that carries a line break" $ do
        let broken = withFirst (\t -> t{bundleTxEffects = ["two\nlines"]})
        case decodeBundle (encodeBundle broken) of
            Left (BundleField "effects" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "refuses bytes that are not JSON" $
        case decodeBundle "not json" of
            Left (BundleField "bundle" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)

-- * The schema

theSchema :: Spec
theSchema = describe "the version 1 schema" $ do
    it "writes exactly the version 1 keys" $ do
        case eitherDecodeStrict sampleBytes of
            Right (Object o) -> do
                sort (map Key.toString (KeyMap.keys o))
                    `shouldBe` [ "command"
                               , "networkMagic"
                               , "signers"
                               , "stateToken"
                               , "transactions"
                               , "version"
                               ]
                KeyMap.lookup "version" o `shouldBe` Just (Number 1)
                case KeyMap.lookup "transactions" o of
                    Just (Array txs) -> do
                        V.length txs `shouldBe` 2
                        mapM_
                            ( \case
                                Object t -> do
                                    sort (map Key.toString (KeyMap.keys t))
                                        `shouldBe` [ "deadline"
                                                   , "effects"
                                                   , "envelope"
                                                   , "identity"
                                                   ]
                                    case KeyMap.lookup "envelope" t of
                                        Just (Object e) ->
                                            sort (map Key.toString (KeyMap.keys e))
                                                `shouldBe` ["cborHex", "description", "type"]
                                        other -> expectationFailure (show other)
                                other -> expectationFailure (show other)
                            )
                            txs
                    other -> expectationFailure (show other)
            other -> expectationFailure (show other)
    it "carries the state token verbatim and never reads it" $ do
        let token = "{\"opaque\": [1, 2, 3]} not parsed"
            bundle = sampleBundle{bundleStateToken = Just token}
        fmap bundleStateToken (decodeBundle (encodeBundle bundle))
            `shouldBe` Right (Just token)
        fmap bundleStateToken (decodeBundle sampleBytes)
            `shouldBe` Right Nothing
    it "accepts a bundle that omits the state token" $ do
        let omitted = tamperJson (KeyMap.delete "stateToken") sampleBytes
        decodeBundle omitted `shouldBe` Right sampleBundle
    it "ignores keys it does not read" $ do
        let extended =
                tamperJson (KeyMap.insert "note" (String "ignored")) sampleBytes
        decodeBundle extended `shouldBe` Right sampleBundle
    it "refuses a state token that is neither text nor null" $ do
        let tampered =
                tamperJson (KeyMap.insert "stateToken" (Number 3)) sampleBytes
        case decodeBundle tampered of
            Left (BundleField "stateToken" _) -> pure ()
            other -> expectationFailure ("refused otherwise: " <> show other)

-- * The offline checks

theOfflineChecks :: Spec
theOfflineChecks = describe "the offline checks" $ do
    it "accepts the sample bundle" $ do
        checkBundle sampleBundle `shouldBe` Right ()
        bundleRefusals sampleBundle `shouldBe` []
    it
        "refuses a recorded identity that is not the body's hash, naming both"
        $ do
            let actual = identityOf (txOf (syntheticBody 1000))
                recorded = flippedIdentity actual
                tampered = withFirst (\t -> t{bundleTxIdentity = recorded})
            checkBundle tampered
                `shouldBe` Left (BundleIdentityMismatch recorded actual)
            case checkBundle tampered of
                Left refusal -> do
                    renderBundleRefusal refusal
                        `shouldMention` "is not the hash of its body"
                    renderBundleRefusal refusal `shouldContainText` hexOf recorded
                    renderBundleRefusal refusal `shouldContainText` hexOf actual
                Right () -> expectationFailure "the tampered bundle was accepted"
    it
        "refuses a recorded deadline that is not the body's bound, naming both"
        $ do
            let tx = txOf (syntheticBody 1000)
                tampered = withFirst (\t -> t{bundleTxDeadline = Just 4000})
            checkBundle tampered
                `shouldBe` Left
                    ( BundleDeadlineMismatch
                        (Just 4000)
                        (deadlineOfTx tx)
                        (identityOf tx)
                    )
    it "refuses a null deadline on a bounded body" $ do
        let tx = txOf (syntheticBody 1000)
            tampered = withFirst (\t -> t{bundleTxDeadline = Nothing})
        checkBundle tampered
            `shouldBe` Left
                ( BundleDeadlineMismatch
                    Nothing
                    (deadlineOfTx tx)
                    (identityOf tx)
                )
    it "accepts a null deadline on an unbounded body" $ do
        let unbounded =
                txOf
                    ( mkBasicTxBody
                        & vldtTxBodyL .~ ValidityInterval SNothing SNothing
                    )
            bundle' =
                sampleBundle
                    { bundleTransactions = bundleTxOf unbounded [] :| []
                    }
        checkBundle bundle' `shouldBe` Right ()
    it "refuses one identity naming two transactions" $ do
        let tx = txOf (syntheticBody 1000)
            one = bundleTxOf tx ["first"]
            again = bundleTxOf tx ["second"]
        case checkBundle sampleBundle{bundleTransactions = one :| [again]} of
            Left (BundleDuplicateIdentity identity) ->
                identity `shouldBe` identityOf tx
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "accepts a body whose required signers the signers cover" $ do
        let requiring =
                txOf
                    ( syntheticBodyRequiring 1000 (Set.singleton (requiredHashOf fixedKey))
                    )
            bundle' =
                sampleBundle
                    { bundleTransactions = bundleTxOf requiring [] :| []
                    }
        checkBundle bundle' `shouldBe` Right ()
    it "refuses a required signer no address covers, naming it" $ do
        let outsider = runtimeKey 0x07
            requiring =
                txOf
                    ( syntheticBodyRequiring 1000 (Set.singleton (requiredHashOf outsider))
                    )
            bundle' =
                sampleBundle
                    { bundleTransactions = bundleTxOf requiring [] :| []
                    }
        checkBundle bundle'
            `shouldBe` Left
                ( BundleSignerNotCovered
                    (keyHashBytes outsider)
                    (identityOf requiring)
                )
    it "covers a signer by the payment key hash of any listed address" $ do
        let requiring =
                txOf
                    ( syntheticBodyRequiring
                        1000
                        (Set.singleton (requiredHashOf strangerKey))
                    )
            bundle' =
                sampleBundle
                    { bundleSigners =
                        fixedSigner :| [addressText (addressOf strangerKey)]
                    , bundleTransactions = bundleTxOf requiring [] :| []
                    }
        checkBundle bundle' `shouldBe` Right ()
    it "refuses an envelope whose CBOR is not a decodable transaction" $ do
        let tx = txOf (syntheticBody 1000)
            undecodable =
                (bundleTxOf tx [])
                    { bundleTxEnvelope =
                        (envelopeOfTx tx){envelopeCborHex = "ff00"}
                    }
        case checkBundle sampleBundle{bundleTransactions = undecodable :| []} of
            Left (BundleEnvelopeUndecodable identity) ->
                identity `shouldBe` hexOf (identityOf tx)
            other -> expectationFailure ("refused otherwise: " <> show other)
    it "names the failed check at the start of every rendered line" $ do
        let tx = txOf (syntheticBody 1000)
            requiring =
                txOf
                    ( syntheticBodyRequiring
                        1001
                        (Set.singleton (requiredHashOf strangerKey))
                    )
            expectations =
                [ (BundleUnknownVersion 2, "version")
                , (BundleField "networkMagic" "is missing", "field")
                , (BundleEnvelopeWrongType "x", "envelope-type")
                , (BundleEnvelopeUndecodable (hexOf (identityOf tx)), "envelope")
                , (BundleIdentityMismatch "a" "b", "identity")
                , (BundleDeadlineMismatch Nothing (Just 1) "i", "deadline")
                , (BundleDuplicateIdentity (identityOf tx), "distinct-identities")
                , (BundleSignerNotCovered "k" (identityOf requiring), "signers")
                ]
        mapM_
            ( \(refusal, name) -> do
                let line = renderBundleRefusal refusal
                (name <> ": ") `shouldSatisfy` (`isPrefixOf` line)
                line `shouldSatisfy` notElem '\n'
            )
            expectations
    it "never mentions the tool a bundle came from" $
        mapM_
            ( \refusal ->
                map toLower (renderBundleRefusal refusal)
                    `shouldNotSatisfy` isInfixOf "singular"
            )
            [ BundleUnknownVersion 2
            , BundleField "networkMagic" "is missing"
            , BundleEnvelopeWrongType "x"
            ]

shouldContainText :: String -> String -> Expectation
shouldContainText haystack needle =
    haystack `shouldSatisfy` isInfixOf needle

-- * Every failure is reported

everyFailureIsReported :: Spec
everyFailureIsReported =
    describe
        "one function reports every failed check, the other the first"
        $ do
            it
                "reports every fault of a generated bundle, in the order of the checks"
                $ property
                $ checkCoverage
                $ forAll genSlots
                $ \slots ->
                    let kinds = scenarioFailedChecks slots
                    in  coverKinds kinds $
                            bundleRefusals (scenarioBundle slots)
                                === scenarioRefusals slots
            it "reports the first of them as the check's refusal" $
                property $
                    forAll genSlots $ \slots ->
                        checkBundle (scenarioBundle slots)
                            === case scenarioRefusals slots of
                                [] -> Right ()
                                r : _ -> Left r
            it "reports an identity, a deadline and an uncovered signer at once" $ do
                let slots =
                        [ Slot 0 True True False
                        , Slot 1 False False False
                        ]
                scenarioFailedChecks slots
                    `shouldBe` ["identity", "deadline", "signers"]
                length (bundleRefusals (scenarioBundle slots)) `shouldBe` 3
            it "reports nothing for a bundle with no fault" $
                bundleRefusals
                    (scenarioBundle [Slot 0 False False False, Slot 2 False False False])
                    `shouldBe` []

-- * The identity is the body hash

theIdentityIsTheBodyHash :: Spec
theIdentityIsTheBodyHash = describe "the identity is the body hash" $ do
    it "equals an independent blake2b-256 of the body bytes" $ do
        let body = syntheticBody 1000
        bodyIdentity (txOf body) `shouldBe` independentBodyHash body
        bodyIdentity (txOf body) `shouldBe` identityOf (txOf body)
    it "is 32 bytes and differs for different bodies" $ do
        let one = bodyIdentity (txOf (syntheticBody 1000))
            other = bodyIdentity (txOf (syntheticBody 1001))
        BS.length one `shouldBe` 32
        one `shouldNotBe` other
    it "reads the deadline from the validity upper bound" $ do
        bodyDeadline (txOf (syntheticBody 1000)) `shouldBe` Just 1000
        bodyDeadline (unboundedBody fixedKey (funding 1)) `shouldBe` Nothing

-- * The committed fixture

theCommittedFixture :: Spec
theCommittedFixture = describe "a bundle written by another tool" $ do
    it "is exactly what this encoder writes for the same bundle" $ do
        committed <- readBundleFixture "unsigned-bundle.json"
        committed `shouldBe` encodeBundle fixtureBundle
    it "decodes unchanged and passes the offline checks" $ do
        committed <- readBundleFixture "unsigned-bundle.json"
        decodeBundle committed `shouldBe` Right fixtureBundle
        checkBundle fixtureBundle `shouldBe` Right ()
        bundleRefusals fixtureBundle `shouldBe` []

-- * The documented example

{- | The example the bundle page shows is a file the page includes, so
what a reader copies is what the codec reads.
-}
theDocumentedExample :: Spec
theDocumentedExample = describe "the example the documentation shows" $ do
    it "decodes to the sample bundle and passes the offline checks" $ do
        shown <- readBundleFixture "example-bundle.json"
        decodeBundle shown `shouldBe` Right sampleBundle
        checkBundle sampleBundle `shouldBe` Right ()

{- | Require that the generated bundles exercise every kind of fault, no
fault at all, and several kinds of fault at once, so a property over
them cannot pass by never meeting the case it is about.
-}
coverKinds :: [String] -> Property -> Property
coverKinds kinds =
    cover 15 ("envelope" `elem` kinds) "an undecodable envelope"
        . cover 15 ("identity" `elem` kinds) "a wrong identity"
        . cover 15 ("deadline" `elem` kinds) "a wrong deadline"
        . cover 10 ("distinct-identities" `elem` kinds) "a repeated identity"
        . cover 15 ("signers" `elem` kinds) "an uncovered signer"
        . cover 3 (null kinds) "no fault"
        . cover 20 (length (nub kinds) >= 2) "several kinds at once"

-- * A bundle around the official envelope

theOfficialEnvelope :: Spec
theOfficialEnvelope = describe "a bundle around the official envelope" $ do
    it "passes the checks, identity and deadline from the ledger" $ do
        (envelope, tx) <- readOfficialTransaction
        let wrapped =
                sampleBundle
                    { bundleTransactions =
                        bundleTxRecording (identityOf tx) (deadlineOfTx tx) envelope
                            :| []
                    }
        checkBundle wrapped `shouldBe` Right ()
        bundleRefusals wrapped `shouldBe` []
    it "refuses a flipped identity, naming both" $ do
        (envelope, tx) <- readOfficialTransaction
        let flipped = flippedIdentity (identityOf tx)
            wrapped =
                sampleBundle
                    { bundleTransactions =
                        bundleTxRecording flipped (deadlineOfTx tx) envelope :| []
                    }
        checkBundle wrapped
            `shouldBe` Left (BundleIdentityMismatch flipped (identityOf tx))
