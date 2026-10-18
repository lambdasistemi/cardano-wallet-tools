{-# LANGUAGE LambdaCase #-}

{- |
Module      : Cardano.Wallet.Tools.Ledger.SubmitSpec
Description : Planning the submission of a signed bundle without sending anything twice
License     : Apache-2.0

One row per promise the planner makes to the signer who hands back the
witnesses: a witness belongs to the body its signature verifies over,
the keys a transaction needs are read from its required signers and the
outputs it spends, the plan keeps the bundle's order and skips what the
chain holds, and every refusal is raised before the plan holds a send
step.

Every expected value is obtained at run time from a producer: the
identities from the ledger's transaction ids, the witnesses from a
signing primitive over the identity bytes, the key hashes from the
keys.
-}
module Cardano.Wallet.Tools.Ledger.SubmitSpec (spec) where

import Cardano.Ledger.Api.Tx (bodyTxL)
import Cardano.Ledger.Api.Tx.Body
    ( collateralInputsTxBodyL
    , inputsTxBodyL
    , reqSignerHashesTxBodyL
    )
import Cardano.Ledger.Api.Tx.Out (TxOut)
import Cardano.Ledger.BaseTypes (SlotNo (..))
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.TxIn (TxIn)
import Cardano.Wallet.Tools.Ledger.Bundle
import Cardano.Wallet.Tools.Ledger.Envelope (TextEnvelope (..))
import Cardano.Wallet.Tools.Ledger.Submit
import Cardano.Wallet.Tools.Sign (DetachedWitness (..))
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Foldable (toList)
import Data.List (isInfixOf)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Word (Word64)
import Lens.Micro ((&), (.~), (^.))
import Support.Ledger
import Support.LedgerScenario
import Test.Hspec
import Test.QuickCheck (choose, forAll, property, (===))

spec :: Spec
spec = describe "submitting a signed bundle" $ do
    pairing
    neededKeysRows
    thePlan
    witnessesOfHeldTransactions
    pendingBodiesAreJudgedAlike
    refusalsComeFirst

-- * Producers

signerHash :: ByteString
signerHash = keyHashBytes fixedKey

{- | The resolver a sound caller supplies: every genuinely external
input beside the outputs the bundle's own earlier bodies produce.
-}
resolvedOf :: [ConwayTx] -> Map TxIn (TxOut ConwayEra)
resolvedOf bodies =
    Map.union
        ( Map.fromList
            [ (funding n, paymentOutput (addressOf fixedKey))
            | n <- [1 .. 6 :: Int]
            ]
        )
        (Map.fromList (outputsOfBodies bodies))

notOnChainOf :: [ConwayTx] -> Map ByteString InclusionStatus
notOnChainOf bodies =
    Map.fromList [(identityOf body, NotOnChain) | body <- bodies]

witnessesOf :: [ConwayTx] -> [DetachedWitness]
witnessesOf bodies = [witnessOver fixedKey body | body <- bodies]

planOf :: [ConwayTx] -> Word64 -> Either SubmitRefusal [PlanStep]
planOf bodies tip =
    fmap
        toList
        ( planSubmission
            (bundleOf bodies)
            (witnessesOf bodies)
            (resolvedOf bodies)
            (notOnChainOf bodies)
            tip
        )

planWith
    :: [ConwayTx]
    -> [DetachedWitness]
    -> Map TxIn (TxOut ConwayEra)
    -> Map ByteString InclusionStatus
    -> Either SubmitRefusal [PlanStep]
planWith bodies witnesses resolved statuses =
    fmap
        toList
        (planSubmission (bundleOf bodies) witnesses resolved statuses 0)

data StepAction = Send | Found
    deriving stock (Eq, Show)

stepAction :: PlanStep -> StepAction
stepAction = \case
    PlanSend{} -> Send
    PlanFound{} -> Found

stepIdentity :: PlanStep -> ByteString
stepIdentity = \case
    PlanSend t _ _ -> bundleTxIdentity t
    PlanFound t _ _ -> bundleTxIdentity t

stepFoundPoint :: PlanStep -> Maybe (ChainPoint, Word64)
stepFoundPoint = \case
    PlanFound _ point confirmations -> Just (point, confirmations)
    PlanSend{} -> Nothing

-- | The witnesses a step carries, whole: none for a found one.
stepWitnesses :: PlanStep -> [DetachedWitness]
stepWitnesses = \case
    PlanSend _ _ witnesses -> witnesses
    PlanFound{} -> []

firstBody :: [ConwayTx] -> ConwayTx
firstBody (b : _) = b
firstBody [] = error "the chained fixture did not build its bodies"

-- | The wallet's own witness over a body.
walletWitness :: ConwayTx -> DetachedWitness
walletWitness = witnessOver fixedKey

placed :: Bool -> InclusionStatus
placed landed
    | landed = IncludedAt (At (SlotNo 9) (BC.replicate 32 '\1')) 4
    | otherwise = NotOnChain

spentBy :: ConwayTx -> [TxIn]
spentBy body = Set.toList (body ^. bodyTxL . inputsTxBodyL)

{- | What the chain shows when the first body has landed or not: found at
a point, and the input it spent no longer there; or not found, its
input still held. The second body is never on the chain.
-}
chainAfter
    :: Bool
    -> [ConwayTx]
    -> (Map TxIn (TxOut ConwayEra), Map ByteString InclusionStatus)
chainAfter landed bodies =
    ( if landed
        then foldr Map.delete (resolvedOf bodies) (spentBy (firstBody bodies))
        else resolvedOf bodies
    , Map.fromList
        [ (identityOf (firstBody bodies), placed landed)
        , (identityOf (last bodies), NotOnChain)
        ]
    )

-- | Every body landed: none of their inputs remain, all are found.
chainAfterAll
    :: [ConwayTx]
    -> (Map TxIn (TxOut ConwayEra), Map ByteString InclusionStatus)
chainAfterAll bodies =
    ( foldr Map.delete (resolvedOf bodies) (concatMap spentBy bodies)
    , Map.fromList [(identityOf b, placed True) | b <- bodies]
    )

-- * Pairing witnesses with bodies

pairing :: Spec
pairing = describe "pairing witnesses with bodies" $ do
    it "pairs each witness with the body its signature verifies over" $ do
        let bodies = chainedBodies 1000
            bundle = bundleOf bodies
            -- supplied in reverse body order: pairing cannot be by position
            witnesses =
                reverse (map (witnessOver fixedKey) bodies)
                    ++ reverse (map (witnessOver strangerKey) bodies)
        case matchWitnesses bundle witnesses of
            Left refusal ->
                expectationFailure ("a sound witness was refused: " <> show refusal)
            Right paired -> do
                Map.keysSet paired `shouldBe` Set.fromList (map identityOf bodies)
                forM_ bodies $ \body ->
                    Map.findWithDefault [] (identityOf body) paired
                        `shouldMatchList` [ witnessOver key body
                                          | key <- [fixedKey, strangerKey]
                                          ]
    it
        "refuses a witness that verifies against no body, naming its public key"
        $ do
            let bodies = chainedBodies 1000
                foreignBody = txOf (syntheticBody 2000)
                foreignWitness = witnessOver fixedKey foreignBody
            case matchWitnesses (bundleOf bodies) [foreignWitness] of
                Left refusal@SubmitWitnessForeignBody{} -> do
                    renderSubmitRefusal refusal
                        `shouldSatisfy` isInfixOf (hexOf (verKeyBytes fixedKey))
                    forM_ bodies $ \body ->
                        renderSubmitRefusal refusal
                            `shouldNotSatisfy` isInfixOf (hexOf (identityOf body))
                other ->
                    expectationFailure ("expected a foreign-body refusal: " <> show other)
    it
        "pairs by the hash of the body, not by the identity the bundle records"
        $ do
            let bodies = chainedBodies 1000
                honest = bundleOf bodies
                recorded = flippedIdentity (identityOf (firstBody bodies))
                tampered =
                    honest
                        { bundleTransactions =
                            case toList (bundleTransactions honest) of
                                t : ts -> t{bundleTxIdentity = recorded} :| ts
                                [] -> error "no transactions"
                        }
                overRecorded = witnessOverMessage fixedKey recorded
                overBody = witnessOver fixedKey (firstBody bodies)
            case matchWitnesses tampered [overRecorded] of
                Left SubmitWitnessForeignBody{} -> pure ()
                other -> expectationFailure ("expected a foreign witness: " <> show other)
            matchWitnesses tampered [overBody]
                `shouldBe` Right (Map.singleton recorded [overBody])
    it "refuses a signature that does not verify, whatever the key" $ do
        let bodies = chainedBodies 1000
            good = witnessOver fixedKey (firstBody bodies)
            flipped =
                good
                    { detachedWitnessSignature =
                        flippedIdentity (detachedWitnessSignature good)
                    }
        case matchWitnesses (bundleOf bodies) [flipped] of
            Left SubmitWitnessForeignBody{} -> pure ()
            other -> expectationFailure ("expected a foreign witness: " <> show other)
    it "refuses a signature over the body bytes rather than the identity" $ do
        let bodies = chainedBodies 1000
            overBytes = witnessOverMessage fixedKey (bodyBytesOf (firstBody bodies))
        case matchWitnesses (bundleOf bodies) [overBytes] of
            Left SubmitWitnessForeignBody{} -> pure ()
            other -> expectationFailure ("expected a foreign witness: " <> show other)

-- * The key hashes that need a witness

neededKeysRows :: Spec
neededKeysRows = describe "the key hashes that need a witness" $ do
    it
        "needs each required signer and the payment key of every input and collateral output; a script credential adds nothing"
        $ do
            let input = funding 1
                collateralInput = funding 2
                body =
                    txOf
                        ( spendingBody fixedKey [input] 1000
                            & reqSignerHashesTxBodyL .~ Set.singleton (requiredHashOf fixedKey)
                            & collateralInputsTxBodyL .~ Set.singleton collateralInput
                        )
                resolved =
                    Map.fromList
                        [ (input, paymentOutput (addressOf strangerKey))
                        , (collateralInput, paymentOutput (addressOf thirdKey))
                        ]
            case neededKeys (bundleOf [body]) resolved of
                Left refusal ->
                    expectationFailure ("needed keys refused: " <> show refusal)
                Right needed ->
                    Map.lookup (identityOf body) needed
                        `shouldBe` Just
                            ( Set.fromList
                                [ signerHash
                                , keyHashBytes strangerKey
                                , keyHashBytes thirdKey
                                ]
                            )
    it "adds no key for a script-credential output the body spends" $ do
        let input = funding 1
            body = txOf (spendingBody fixedKey [input] 1000)
            resolved = Map.singleton input (scriptOutput 7)
        case neededKeys (bundleOf [body]) resolved of
            Left refusal ->
                expectationFailure ("needed keys refused: " <> show refusal)
            Right needed ->
                Map.lookup (identityOf body) needed `shouldBe` Just Set.empty
    it "needs the required signer alone when no input adds a key" $ do
        let body =
                txOf
                    ( syntheticBody 1000
                        & reqSignerHashesTxBodyL .~ Set.singleton (requiredHashOf fixedKey)
                    )
        case neededKeys (bundleOf [body]) Map.empty of
            Left refusal ->
                expectationFailure ("needed keys refused: " <> show refusal)
            Right needed ->
                Map.lookup (identityOf body) needed
                    `shouldBe` Just (Set.singleton signerHash)
    it
        "needs the payment key of an input alone when no signer is required"
        $ do
            let body = txOf (spendingBody fixedKey [funding 1] 1000)
                resolved =
                    Map.singleton (funding 1) (paymentOutput (addressOf strangerKey))
            case neededKeys (bundleOf [body]) resolved of
                Left refusal ->
                    expectationFailure ("needed keys refused: " <> show refusal)
                Right needed ->
                    Map.lookup (identityOf body) needed
                        `shouldBe` Just (Set.singleton (keyHashBytes strangerKey))
    it "needs the payment key of a collateral input alone" $ do
        let body =
                txOf
                    ( syntheticBody 1000
                        & collateralInputsTxBodyL .~ Set.singleton (funding 2)
                    )
            resolved =
                Map.singleton (funding 2) (paymentOutput (addressOf thirdKey))
        case neededKeys (bundleOf [body]) resolved of
            Left refusal ->
                expectationFailure ("needed keys refused: " <> show refusal)
            Right needed ->
                Map.lookup (identityOf body) needed
                    `shouldBe` Just (Set.singleton (keyHashBytes thirdKey))
    it
        "reads an input produced by an earlier body of the bundle from that body"
        $ do
            let bodies = chainedBodies 1000
                second = last bodies
                produced = Map.fromList (outputsOfBodies [firstBody bodies])
            case Set.toList (second ^. bodyTxL . inputsTxBodyL) of
                [secondInput] ->
                    case Map.lookup secondInput produced of
                        Nothing ->
                            expectationFailure "the earlier body does not produce the input"
                        Just out ->
                            case neededKeys
                                (bundleOf bodies)
                                ( Map.union
                                    ( Map.fromList
                                        [ (funding n, paymentOutput (addressOf fixedKey))
                                        | n <- [1 .. 6 :: Int]
                                        ]
                                    )
                                    (Map.singleton secondInput out)
                                ) of
                                Left refusal ->
                                    expectationFailure ("needed keys refused: " <> show refusal)
                                Right needed ->
                                    Map.lookup (identityOf second) needed
                                        `shouldBe` Just (Set.singleton signerHash)
                other ->
                    expectationFailure
                        ("the second body does not spend exactly one input: " <> show other)
    it "refuses an input neither produced by an earlier body nor resolved" $ do
        let bodies = chainedBodies 1000
        case neededKeys (bundleOf bodies) Map.empty of
            Left refusal@SubmitInputUnresolved{} ->
                renderSubmitRefusal refusal
                    `shouldSatisfy` isInfixOf (txInHex (funding 1))
            other ->
                expectationFailure ("expected an unresolved input: " <> show other)
    it "refuses a collateral input that is not resolved" $ do
        let body =
                txOf
                    ( syntheticBody 1000
                        & collateralInputsTxBodyL .~ Set.singleton (funding 2)
                    )
        case neededKeys (bundleOf [body]) Map.empty of
            Left (SubmitInputUnresolved reference) ->
                reference `shouldBe` funding 2
            other ->
                expectationFailure ("expected an unresolved input: " <> show other)

-- * The plan of what to send

thePlan :: Spec
thePlan = describe "the plan of what to send" $ do
    it "sends the bundle's transactions in order when none is on chain" $ do
        let bodies = chainedBodies 1000
        case planOf bodies 0 of
            Left refusal ->
                expectationFailure ("a sound bundle was refused: " <> show refusal)
            Right steps -> do
                map stepAction steps `shouldBe` [Send, Send]
                map stepIdentity steps `shouldBe` map identityOf bodies
    it "sends each body with exactly its verified witnesses" $ do
        let bodies = chainedBodies 1000
        case planOf bodies 0 of
            Left refusal ->
                expectationFailure ("a sound bundle was refused: " <> show refusal)
            Right steps ->
                [ [ (detachedWitnessVKey w, detachedWitnessSignature w)
                  | w <- ws
                  ]
                | PlanSend _ _ ws <- steps
                ]
                    `shouldBe` [ [
                                     ( verKeyBytes fixedKey
                                     , detachedWitnessSignature (witnessOver fixedKey body)
                                     )
                                 ]
                               | body <- bodies
                               ]
    it "skips a transaction the chain already holds, by its identity" $ do
        let bodies = chainedBodies 1000
            point = At (SlotNo 9) (BC.replicate 32 '\1')
            statuses =
                Map.fromList
                    [ (identityOf (firstBody bodies), IncludedAt point 4)
                    , (identityOf (last bodies), NotOnChain)
                    ]
        case planSubmission
            (bundleOf bodies)
            (witnessesOf bodies)
            (resolvedOf bodies)
            statuses
            100 of
            Left refusal ->
                expectationFailure
                    ("a found transaction stopped the run: " <> show refusal)
            Right steps -> case toList steps of
                [found, send] -> do
                    stepAction found `shouldBe` Found
                    stepFoundPoint found `shouldBe` Just (point, 4)
                    stepAction send `shouldBe` Send
                    stepIdentity send `shouldBe` identityOf (last bodies)
                other ->
                    expectationFailure
                        ("expected one found step and one send: " <> show other)
    it "plans only found steps when the chain holds every body" $ do
        let bodies = chainedBodies 1000
            statuses =
                Map.fromList
                    [ (identityOf b, IncludedAt (At (SlotNo 1) (BS.replicate 32 2)) 2)
                    | b <- bodies
                    ]
        case planSubmission
            (bundleOf bodies)
            (witnessesOf bodies)
            (resolvedOf bodies)
            statuses
            100 of
            Left refusal ->
                expectationFailure
                    ("an all-found bundle was refused: " <> show refusal)
            Right steps -> do
                map stepAction (toList steps) `shouldBe` [Found, Found]
                map stepIdentity (toList steps) `shouldBe` map identityOf bodies
    it
        "refuses an expired body with the word rebuild at and past the bound, never one slot before it"
        $ do
            let bodies = chainedBodies 1000
                bound = 1000 :: Word64
            forM_ [(bound - 1, False), (bound, True), (bound + 1, True)] $
                \(tip, expired) ->
                    case planOf bodies tip of
                        Left refusal@(SubmitBodyExpired _ readBound readTip) -> do
                            expired `shouldBe` True
                            readBound `shouldBe` bound
                            readTip `shouldBe` tip
                            renderSubmitRefusal refusal `shouldSatisfy` isInfixOf "rebuild"
                        other -> do
                            expired `shouldBe` False
                            case other of
                                Left refusal ->
                                    expectationFailure
                                        ("refused before the bound: " <> show refusal)
                                Right steps -> length steps `shouldBe` 2
    it "never refuses a body with no validity upper bound" $ do
        let bodies =
                [ unboundedBody fixedKey (funding 1)
                , unboundedBody fixedKey (funding 3)
                ]
        case planSubmission
            (bundleOf bodies)
            (witnessesOf bodies)
            (resolvedOf bodies)
            (notOnChainOf bodies)
            (10 ^ (12 :: Int)) of
            Left refusal ->
                expectationFailure ("an unbounded body was refused: " <> show refusal)
            Right steps -> do
                map stepAction (toList steps) `shouldBe` [Send, Send]
                map stepIdentity (toList steps) `shouldBe` map identityOf bodies
    it "never judges the expiry of a body the chain holds" $ do
        let bodies = chainedBodies 1000
            (resolved, statuses) = chainAfterAll bodies
        case planSubmission
            (bundleOf bodies)
            (witnessesOf bodies)
            resolved
            statuses
            (10 ^ (12 :: Int)) of
            Left refusal ->
                expectationFailure ("a held body expired: " <> show refusal)
            Right steps -> map stepAction (toList steps) `shouldBe` [Found, Found]
    it "refuses a missing witness as incomplete, before any send" $ do
        let bodies = chainedBodies 1000
            firstWitnesses = [witnessOver fixedKey (firstBody bodies)]
        case planSubmission
            (bundleOf bodies)
            firstWitnesses
            (resolvedOf bodies)
            (notOnChainOf bodies)
            0 of
            Left refusal@(SubmitWitnessMissing keyHash identity) -> do
                keyHash `shouldBe` signerHash
                identity `shouldBe` identityOf (last bodies)
                renderSubmitRefusal refusal
                    `shouldSatisfy` isInfixOf "needs a witness"
            other ->
                expectationFailure ("expected a missing witness: " <> show other)
    it "refuses a single valid witness for a key no transaction needs" $ do
        let bodies = chainedBodies 1000
            strangerWitness = witnessOver strangerKey (firstBody bodies)
        case planSubmission
            (bundleOf bodies)
            [strangerWitness]
            (resolvedOf bodies)
            (notOnChainOf bodies)
            0 of
            Left refusal@(SubmitWitnessUnneededKey keyHash) -> do
                keyHash `shouldBe` keyHashBytes strangerKey
                renderSubmitRefusal refusal
                    `shouldSatisfy` isInfixOf "needs no witness"
            other ->
                expectationFailure ("expected an unneeded key: " <> show other)
    it "refuses a duplicate of a needed witness as its own refusal" $ do
        let bodies = chainedBodies 1000
            witness = witnessOver fixedKey (firstBody bodies)
        case planSubmission
            (bundleOf bodies)
            [witness, witness]
            (resolvedOf bodies)
            (notOnChainOf bodies)
            0 of
            Left refusal@SubmitWitnessUnneededKey{} ->
                renderSubmitRefusal refusal
                    `shouldSatisfy` isInfixOf "needs no witness"
            other ->
                expectationFailure
                    ("expected the duplicate to be refused: " <> show other)
    it
        "refuses a bundle whose own checks fail, with the first failed check"
        $ do
            let bodies = chainedBodies 1000
                honest = bundleOf bodies
                recorded = flippedIdentity (identityOf (firstBody bodies))
                tampered =
                    honest
                        { bundleTransactions =
                            case toList (bundleTransactions honest) of
                                t : ts -> t{bundleTxIdentity = recorded} :| ts
                                [] -> error "no transactions"
                        }
            planSubmission
                tampered
                (witnessesOf bodies)
                (resolvedOf bodies)
                (notOnChainOf bodies)
                0
                `shouldBe` Left
                    ( SubmitBundleRefused
                        (BundleIdentityMismatch recorded (identityOf (firstBody bodies)))
                    )
    it "refuses every generated faulty bundle with its first failed check" $
        property $
            forAll genSlots $ \slots ->
                case scenarioRefusals slots of
                    [] -> property True
                    first : _ ->
                        planSubmission (scenarioBundle slots) [] Map.empty Map.empty 0
                            === Left (SubmitBundleRefused first)

-- * Witnesses of a transaction the chain already holds

witnessesOfHeldTransactions :: Spec
witnessesOfHeldTransactions =
    describe "witnesses of a transaction the chain already holds" $ do
        it
            "sends the second body when the first has landed without its witness"
            $ do
                let bodies = chainedBodies 1000
                    (resolved, statuses) = chainAfter True bodies
                case planWith bodies [walletWitness (last bodies)] resolved statuses of
                    Left refusal ->
                        expectationFailure
                            ("a found body asked for a witness: " <> show refusal)
                    Right steps -> do
                        map stepAction steps `shouldBe` [Found, Send]
                        map stepIdentity steps `shouldBe` map identityOf bodies
                        map stepWitnesses steps
                            `shouldBe` [[], [walletWitness (last bodies)]]
        it
            "refuses the same bundle as incomplete when the first has not landed"
            $ do
                let bodies = chainedBodies 1000
                    (resolved, statuses) = chainAfter False bodies
                case planWith bodies [walletWitness (last bodies)] resolved statuses of
                    Left (SubmitWitnessMissing keyHash identity) -> do
                        keyHash `shouldBe` signerHash
                        identity `shouldBe` identityOf (firstBody bodies)
                    other ->
                        expectationFailure ("expected a missing witness: " <> show other)
        it
            "ignores a stranger's valid witness over a landed body and sends the second"
            $ do
                let bodies = chainedBodies 1000
                    (resolved, statuses) = chainAfter True bodies
                    witnesses =
                        [ witnessOver strangerKey (firstBody bodies)
                        , walletWitness (last bodies)
                        ]
                case planWith bodies witnesses resolved statuses of
                    Left refusal ->
                        expectationFailure
                            ("a witness over a found body was refused: " <> show refusal)
                    Right steps -> do
                        map stepAction steps `shouldBe` [Found, Send]
                        map stepWitnesses steps
                            `shouldBe` [[], [walletWitness (last bodies)]]
        it
            "refuses the same stranger's witness as an unneeded key when the first has not landed"
            $ do
                let bodies = chainedBodies 1000
                    (resolved, statuses) = chainAfter False bodies
                    witnesses =
                        [ witnessOver strangerKey (firstBody bodies)
                        , walletWitness (last bodies)
                        ]
                case planWith bodies witnesses resolved statuses of
                    Left (SubmitWitnessUnneededKey keyHash) ->
                        keyHash `shouldBe` keyHashBytes strangerKey
                    other ->
                        expectationFailure ("expected an unneeded key: " <> show other)
        it
            "still refuses a witness verifying against no body when every body is found"
            $ do
                let bodies = chainedBodies 1000
                    (resolved, statuses) = chainAfterAll bodies
                    own = witnessesOf bodies
                    outsider = witnessOver fixedKey (unboundedBody fixedKey (funding 5))
                case planWith bodies (own <> [outsider]) resolved statuses of
                    Left (SubmitWitnessForeignBody key) ->
                        key `shouldBe` verKeyBytes fixedKey
                    other ->
                        expectationFailure ("expected a foreign witness: " <> show other)
                case planWith bodies own resolved statuses of
                    Left refusal ->
                        expectationFailure ("valid witnesses were refused: " <> show refusal)
                    Right steps -> map stepAction steps `shouldBe` [Found, Found]

-- * Every refusal comes before any send

{- | A refusal about a later transaction leaves no plan at all: the
result is the refusal, never a plan whose first steps could already be
sent.
-}
refusalsComeFirst :: Spec
refusalsComeFirst =
    describe "every refusal is raised before the plan holds a send step" $ do
        let bodies = chainedBodies 1000
            good = witnessesOf bodies
            late =
                [ firstBody bodies
                , txOf (spendingBody fixedKey (spentBy (last bodies)) 5)
                ]
            plan witnesses resolved =
                planSubmission
                    (bundleOf bodies)
                    witnesses
                    resolved
                    (notOnChainOf bodies)
                    0
            checks
                :: [ ( String
                     , Either SubmitRefusal (NonEmpty PlanStep)
                     , SubmitRefusal -> Bool
                     )
                   ]
            checks =
                [
                    ( "a foreign witness"
                    , plan
                        (good <> [witnessOver fixedKey (txOf (syntheticBody 77))])
                        (resolvedOf bodies)
                    , \case SubmitWitnessForeignBody{} -> True; _ -> False
                    )
                ,
                    ( "an unneeded witness"
                    , plan
                        (good <> [witnessOver strangerKey (firstBody bodies)])
                        (resolvedOf bodies)
                    , \case SubmitWitnessUnneededKey{} -> True; _ -> False
                    )
                ,
                    ( "a missing witness for the last transaction"
                    , plan (take 1 good) (resolvedOf bodies)
                    , \case
                        SubmitWitnessMissing _ i -> i == identityOf (last bodies)
                        _ -> False
                    )
                ,
                    ( "an unresolved input of the first transaction"
                    , plan good (Map.delete (funding 1) (resolvedOf bodies))
                    , \case SubmitInputUnresolved i -> i == funding 1; _ -> False
                    )
                ,
                    ( "an expired last transaction"
                    , planSubmission
                        (bundleOf late)
                        (witnessesOf late)
                        (resolvedOf late)
                        (notOnChainOf late)
                        6
                    , \case
                        SubmitBodyExpired i 5 6 -> i == identityOf (last late)
                        _ -> False
                    )
                ]
        forM_ checks $ \(name, result, expected) ->
            it ("leaves no plan for " <> name) $
                case result of
                    Left refusal | expected refusal -> pure ()
                    other -> expectationFailure ("not refused as expected: " <> show other)

-- * What is still to send is judged alike

{- | A transaction is held only when the chain view gives it an inclusion
point. Every other one is still to send, whether the view says it is not
on the chain or says nothing, and is judged by every check the same way.
-}
pendingBodiesAreJudgedAlike :: Spec
pendingBodiesAreJudgedAlike =
    describe
        "a transaction the chain view does not mention is still to send"
        $ do
            it
                "is refused as expired at its bound, as one the view says is not on the chain"
                $ do
                    let bodies = chainedBodies 1000
                    planSubmission
                        (bundleOf bodies)
                        (witnessesOf bodies)
                        (resolvedOf bodies)
                        Map.empty
                        1000
                        `shouldBe` Left
                            (SubmitBodyExpired (identityOf (firstBody bodies)) 1000 1000)
            it
                "is judged exactly as when the view says it is not on the chain, whatever mix of statuses"
                $ property
                $ forAll (choose (0, 1100))
                $ \tip ->
                    forAll (choose (0, 3 :: Int)) $ \mask ->
                        let bodies = chainedBodies 1000
                            full = notOnChainOf bodies
                            keep identity = case mask of
                                0 -> identity == identityOf (firstBody bodies)
                                1 -> identity == identityOf (last bodies)
                                2 -> False
                                _ -> True
                            present = Map.filterWithKey (\identity _ -> keep identity) full
                            plan statuses =
                                planSubmission
                                    (bundleOf bodies)
                                    (witnessesOf bodies)
                                    (resolvedOf bodies)
                                    statuses
                                    tip
                        in  plan present === plan full
            it
                "needs its witnesses and its resolved inputs as when the view says it is not on the chain"
                $ do
                    let bodies = chainedBodies 1000
                    case planSubmission (bundleOf bodies) [] (resolvedOf bodies) Map.empty 0 of
                        Left SubmitWitnessMissing{} -> pure ()
                        other -> expectationFailure ("expected a missing witness: " <> show other)
                    case planSubmission
                        (bundleOf bodies)
                        (witnessesOf bodies)
                        Map.empty
                        Map.empty
                        0 of
                        Left SubmitInputUnresolved{} -> pure ()
                        other ->
                            expectationFailure ("expected an unresolved input: " <> show other)
            it
                "must pass the offline checks: a recorded identity that is not the body's hash is refused"
                $ do
                    let bodies = chainedBodies 1000
                        other = txOf (syntheticBody 77)
                        honest = bundleOf bodies
                        tampered =
                            honest
                                { bundleTransactions =
                                    case toList (bundleTransactions honest) of
                                        one : two : more ->
                                            one :| (two{bundleTxIdentity = identityOf other} : more)
                                        short -> error ("short bundle: " <> show (length short))
                                }
                        -- the key that owns the second body's input signs the
                        -- identity the bundle records instead of the body's hash
                        signedOverRecorded = witnessOverMessage fixedKey (identityOf other)
                    planSubmission
                        tampered
                        [witnessOver fixedKey (firstBody bodies), signedOverRecorded]
                        (resolvedOf bodies)
                        (notOnChainOf bodies)
                        0
                        `shouldBe` Left
                            ( SubmitBundleRefused
                                (BundleIdentityMismatch (identityOf other) (identityOf (last bodies)))
                            )
            it
                "leaves a transaction the chain holds unjudged by the offline checks"
                $ do
                    let bodies = chainedBodies 1000
                        honest = bundleOf bodies
                        recorded = flippedIdentity (identityOf (firstBody bodies))
                        tampered =
                            honest
                                { bundleTransactions =
                                    case toList (bundleTransactions honest) of
                                        one : more ->
                                            one{bundleTxIdentity = recorded} :| more
                                        [] -> error "no transactions"
                                }
                        point = At (SlotNo 9) (BC.replicate 32 '\1')
                        statuses =
                            Map.fromList
                                [ (recorded, IncludedAt point 4)
                                , (identityOf (last bodies), NotOnChain)
                                ]
                    fmap
                        (map stepAction . toList)
                        ( planSubmission
                            tampered
                            [walletWitness (last bodies)]
                            (resolvedOf bodies)
                            statuses
                            0
                        )
                        `shouldBe` Right [Found, Send]
            it
                "leaves a held transaction whose envelope does not decode undecoded"
                $ do
                    let bodies = chainedBodies 1000
                        honest = bundleOf bodies
                        undecodable t =
                            t{bundleTxEnvelope = (bundleTxEnvelope t){envelopeCborHex = "ff00"}}
                        broken =
                            honest
                                { bundleTransactions =
                                    case toList (bundleTransactions honest) of
                                        one : more -> undecodable one :| more
                                        [] -> error "no transactions"
                                }
                        statuses =
                            Map.fromList
                                [
                                    ( identityOf (firstBody bodies)
                                    , IncludedAt (At (SlotNo 9) (BC.replicate 32 '\1')) 4
                                    )
                                , (identityOf (last bodies), NotOnChain)
                                ]
                    fmap
                        (map stepAction . toList)
                        ( planSubmission
                            broken
                            [walletWitness (last bodies)]
                            (resolvedOf bodies)
                            statuses
                            0
                        )
                        `shouldBe` Right [Found, Send]
