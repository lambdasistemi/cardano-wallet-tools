{- |
Module      : Cardano.Wallet.Tools.Vault.PayloadSpec
Description : What a vault holds: the v1 envelope and the tx-sign payload
License     : Apache-2.0

The vault plaintext proofs. The writer emits the key's @cardano-cli@
text envelope and nothing else; the reader also accepts the
@cardano-tx-tools@ @tx-sign vault@ payload, choosing an identity by
label. Expected keys come from the @cardano-cli@ fixture files, read at
run time; the tx-sign vault itself was made by stock @age@.
-}
module Cardano.Wallet.Tools.Vault.PayloadSpec (spec) where

import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase (Passphrase)
import Cardano.Wallet.Tools.Vault.Payload
import Cardano.Wallet.Tools.Vault.Scrypt (openVault, sealVault)
import Control.Monad (forM, forM_)
import Data.Aeson (Value, object, (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.ByteString.Lazy qualified as BSL
import Data.List (nub, sort)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.Vault
import System.Directory (listDirectory)
import System.Exit (ExitCode (..))
import System.FilePath (dropExtension, takeExtension)
import Test.Hspec
import Test.QuickCheck (forAll, property, vectorOf)
import Test.QuickCheck qualified as QC

spec :: Spec
spec = describe "vault v1" $ do
    keyEnvelope
    txSignPayload

-- * Producers

-- | Whether no value repeats.
allDistinct :: (Eq a) => [a] -> Bool
allDistinct xs = length (nub xs) == length xs

-- | A tx-sign payload, built as the cardano-tx-tools encoder lays it out.
txSignPayloadOf :: Int -> [(Text, Value)] -> ByteString
txSignPayloadOf version identities =
    BSL.toStrict . Aeson.encode $
        object
            [ "cardanoTxSignVault"
                .= object
                    [ "version" .= version
                    , "identities"
                        .= object
                            [ Key.fromText label .= identity label source
                            | (label, source) <- identities
                            ]
                    ]
            ]
  where
    identity label source =
        object
            [ "label" .= label
            , "network" .= ("preprod" :: Text)
            , "keyHash" .= keyHashOf source
            , "source" .= source
            ]
    keyHashOf _ = T.replicate 56 "0"

-- | A cardano-cli-skey source holding an envelope.
cliSource :: ByteString -> Value
cliSource envelope =
    object
        [ "kind" .= ("cardano-cli-skey" :: Text)
        , "keyEnvelope"
            .= fromMaybe
                (error "cliSource: not JSON")
                (Aeson.decodeStrict' envelope :: Maybe Value)
        ]

-- | A source of the kind the reader names and refuses.
addressesSource :: Value
addressesSource =
    object
        [ "kind" .= ("cardano-addresses-addr-xsk" :: Text)
        , "bech32" .= ("not parsed: the kind is refused first" :: Text)
        ]

{- | The fixture's identities: label and verification-key bytes, labels
read from the payload, checked against the key files beside it.
-}
fixtureIdentities :: IO [(Text, ByteString)]
fixtureIdentities = do
    labels <-
        sort
            <$> (readFixture "tx-sign/payload.json" >>= identityLabelsOfPayload)
    forM labels $ \label ->
        (,) label
            <$> verificationKeyOfFixture ("tx-sign/" <> T.unpack label <> ".vkey")

fixtureVault :: IO (ByteString, Passphrase)
fixtureVault = do
    bytes <- readFixture "tx-sign/vault.age"
    line <- readFixture "tx-sign/passphrase"
    pure (bytes, passphrase (BC.takeWhile (/= '\n') line))

-- * The v1 envelope

keyEnvelope :: Spec
keyEnvelope = describe "key envelope" $ do
    it "writes the key as a cardano-cli signing-key text envelope" $ do
        skey <- readFixture "payment.skey"
        key <- either (fail . show) pure (parseSigningKeyEnvelope skey)
        envelope <-
            either fail pure . parseEnvelope $ encodeV1Payload key
        original <- either fail pure (parseEnvelope skey)
        envelopeType envelope `shouldBe` "PaymentSigningKeyShelley_ed25519"
        envelopeCborHex envelope `shouldBe` envelopeCborHex original

    it "reads a real cardano-cli signing key to its verification key" $ do
        skey <- readFixture "payment.skey"
        vkey <- verificationKeyOfFixture "payment.vkey"
        key <- either (fail . show) pure (parseSigningKeyEnvelope skey)
        signsAs key vkey

    it "reads back the key it wrote, for any key" $
        property $
            forAll genSeed $ \seed ->
                case parseSigningKeyEnvelope (seedEnvelope seed) of
                    Left _ -> False
                    Right key ->
                        ( parseEnvelope (encodeV1Payload key)
                            >>= secretOfEnvelope
                        )
                            == Right seed

    it "reads the v1 plaintext through the vault reader, selector or not" $ do
        let key = keyFromSeed (seedKey 0x61)
        fmap
            encodeV1Payload
            (decodeVaultPayload Nothing (encodeV1Payload key))
            `shouldBe` Right (encodeV1Payload key)
        fmap
            encodeV1Payload
            ( decodeVaultPayload
                (Just (IdentitySelector "alice"))
                (encodeV1Payload key)
            )
            `shouldBe` Right (encodeV1Payload key)

    it "reads both payment key types a plaintext key file may carry"
        $ forM_
            [ "PaymentSigningKeyShelley_ed25519"
            , "GenesisUTxOSigningKey_ed25519"
            ]
        $ \keyType ->
            parseSigningKeyEnvelope (envelopeOfType keyType (seedKey 0x62))
                `shouldSatisfy` either (const False) (const True)

    it "refuses every plaintext that is not a payment signing key" $ do
        vkeyFixture <- readFixture "payment.vkey"
        txSign <- readFixture "tx-sign/payload.json"
        let intact = seedEnvelope (seedKey 0x63)
            refused :: [(String, ByteString)]
            refused =
                [ ("not JSON", "zzz")
                , ("a JSON array", "[]")
                , ("a verification key", vkeyFixture)
                , ("a tx-sign payload", txSign)
                ,
                    ( "a stake key"
                    , envelopeOfType "StakeSigningKeyShelley_ed25519" (seedKey 0x63)
                    )
                ,
                    ( "an extended key"
                    , envelopeOfType
                        "PaymentExtendedSigningKeyShelley_ed25519_bip32"
                        (seedKey 0x63)
                    )
                ,
                    ( "31 key bytes"
                    , envelopeWithHex ("5820" <> B16.encode (BS.take 31 (seedKey 0x63)))
                    )
                ,
                    ( "33 key bytes"
                    , envelopeWithHex ("5820" <> B16.encode (seedKey 0x63 <> "x"))
                    )
                , ("no CBOR header", envelopeWithHex (B16.encode (seedKey 0x63)))
                , ("a cborHex that is not hex", envelopeWithHex "58zz")
                ,
                    ( "no cborHex"
                    , "{\"type\":\"PaymentSigningKeyShelley_ed25519\"}"
                    )
                ]
        parseSigningKeyEnvelope intact
            `shouldSatisfy` either (const False) (const True)
        forM_ refused $ \(what, bytes) ->
            (what, parseSigningKeyEnvelope bytes)
                `shouldSatisfy` (either (== PayloadNotASigningKey) (const False) . snd)

    it "shows no key byte" $ do
        let seed = "abcdefghijklmnopqrstuvwxyzABCDEF"
            shown = show (keyFromSeed seed)
        BC.pack shown `shouldNotSatisfy` BS.isInfixOf seed
        BC.pack shown `shouldNotSatisfy` BS.isInfixOf (B16.encode seed)

    it "renders each refusal as a line with the labels and no key" $ do
        let seed = "abcdefghijklmnopqrstuvwxyzABCDEF"
            rendered =
                [ renderVaultPayloadRefusal PayloadNotASigningKey
                , renderVaultPayloadRefusal
                    ( PayloadIdentityMissing
                        (Just (IdentitySelector "mallory"))
                        ["alice", "bob"]
                    )
                , renderVaultPayloadRefusal (PayloadSourceUnsupported "xsk")
                ]
        forM_ rendered $ \line ->
            line `shouldNotSatisfy` T.isInfixOf (TE.decodeUtf8 (B16.encode seed))
        rendered !! 1 `shouldSatisfy` T.isInfixOf "mallory"
        rendered !! 1 `shouldSatisfy` T.isInfixOf "alice"
        rendered !! 1 `shouldSatisfy` T.isInfixOf "bob"
        rendered !! 2 `shouldSatisfy` T.isInfixOf "xsk"
  where
    envelopeOfType keyType seed =
        BC.pack $
            "{\"type\":\""
                <> keyType
                <> "\",\"description\":\"spec\",\"cborHex\":\"5820"
                <> BC.unpack (B16.encode seed)
                <> "\"}"
    envelopeWithHex hex =
        "{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"spec\",\"cborHex\":\""
            <> hex
            <> "\"}"

-- | A 32-byte seed.
genSeed :: QC.Gen ByteString
genSeed = BS.pack <$> vectorOf 32 (QC.choose (0, 255))

-- * The tx-sign payload

txSignPayload :: Spec
txSignPayload = describe "tx-sign payload" $ do
    it "holds several identities, as many key files as labels" $ do
        payload <- readFixture "tx-sign/payload.json"
        labels <- sort <$> identityLabelsOfPayload payload
        files <- listDirectory (fixturePath "tx-sign")
        let named = sort [dropExtension f | f <- files, takeExtension f == ".skey"]
        length labels `shouldSatisfy` (> 2)
        map T.unpack labels `shouldBe` named

    it "reads the payload plaintext to each identity's own key" $ do
        payload <- readFixture "tx-sign/payload.json"
        identities <- fixtureIdentities
        forM_ identities $ \(label, vkey) -> do
            key <-
                either (fail . show) pure $
                    decodeVaultPayload (Just (IdentitySelector label)) payload
            signsAs key vkey

    it "gives every identity a different key" $ do
        payload <- readFixture "tx-sign/payload.json"
        identities <- fixtureIdentities
        encoded <- forM identities $ \(label, _) ->
            either (fail . show) (pure . encodeV1Payload) $
                decodeVaultPayload (Just (IdentitySelector label)) payload
        allDistinct encoded `shouldBe` True
        length identities `shouldSatisfy` (> 2)

    it "tells duplicate keys from distinct keys (control)" $ do
        let key seed = encodeV1Payload (keyFromSeed (seedKey seed))
            (a, b, c) = (key 0x71, key 0x72, key 0x73)
        allDistinct [a, b, c] `shouldBe` True
        allDistinct [a, a, a] `shouldBe` False
        allDistinct [a, b, a] `shouldBe` False

    it "opens the stock age vault to the selected identity" $ do
        (vault, pass) <- fixtureVault
        identities <- fixtureIdentities
        forM_ identities $ \(label, vkey) -> do
            key <-
                either (fail . T.unpack . renderVaultRefusal) pure $
                    openVault (Just (IdentitySelector label)) pass vault
            signsAs key vkey

    it "refuses several identities and no selector, naming the labels" $ do
        (vault, pass) <- fixtureVault
        identities <- fixtureIdentities
        let labels = map fst identities
        case openVault Nothing pass vault of
            Left
                refusal@(VaultPayloadRefused (PayloadIdentityMissing Nothing named)) -> do
                    sort named `shouldBe` labels
                    forM_ labels $ \label ->
                        renderVaultRefusal refusal `shouldSatisfy` T.isInfixOf label
            other -> expectationFailure ("not refused by name: " <> show other)

    it "refuses an unknown identity, naming the labels it could take" $ do
        payload <- readFixture "tx-sign/payload.json"
        identities <- fixtureIdentities
        case decodeVaultPayload (Just (IdentitySelector "mallory")) payload of
            Left (PayloadIdentityMissing (Just (IdentitySelector asked)) named) -> do
                asked `shouldBe` "mallory"
                sort named `shouldBe` map fst identities
            other -> expectationFailure ("not refused by name: " <> show other)

    it "takes the single identity when no selector is given" $ do
        skey <- readFixture "tx-sign/bob.skey"
        vkey <- verificationKeyOfFixture "tx-sign/bob.vkey"
        let payload = txSignPayloadOf 1 [("bob", cliSource skey)]
        key <- either (fail . show) pure (decodeVaultPayload Nothing payload)
        signsAs key vkey
        decodeVaultPayload (Just (IdentitySelector "alice")) payload
            `shouldSatisfy` either (const True) (const False)

    it
        "refuses an identity whose source is not a cardano-cli key, by kind"
        $ do
            skey <- readFixture "tx-sign/bob.skey"
            let payload =
                    txSignPayloadOf
                        1
                        [("bob", cliSource skey), ("xsk", addressesSource)]
            decodeVaultPayload (Just (IdentitySelector "xsk")) payload
                `shouldSatisfy` either
                    (== PayloadSourceUnsupported "cardano-addresses-addr-xsk")
                    (const False)

    it
        "refuses an unknown source kind by its kind, even holding a key envelope"
        $ do
            skey <- readFixture "tx-sign/bob.skey"
            let hardware =
                    object
                        [ "kind" .= ("hardware-wallet" :: Text)
                        , "keyEnvelope"
                            .= fromMaybe
                                (error "hardware: not JSON")
                                (Aeson.decodeStrict' skey :: Maybe Value)
                        ]
            decodeVaultPayload
                (Just (IdentitySelector "foreign"))
                (txSignPayloadOf 1 [("foreign", hardware)])
                `shouldSatisfy` either
                    (== PayloadSourceUnsupported "hardware-wallet")
                    (const False)

    it "opens a cardano-cli identity beside a source it does not read" $ do
        skey <- readFixture "tx-sign/bob.skey"
        vkey <- verificationKeyOfFixture "tx-sign/bob.vkey"
        let payload =
                txSignPayloadOf
                    1
                    [("bob", cliSource skey), ("xsk", addressesSource)]
        key <-
            either (fail . show) pure $
                decodeVaultPayload (Just (IdentitySelector "bob")) payload
        signsAs key vkey

    it "refuses a payload that is not version 1, or whose labels disagree" $ do
        skey <- readFixture "tx-sign/bob.skey"
        let versionTwo = txSignPayloadOf 2 [("bob", cliSource skey)]
            mislabelled =
                BSL.toStrict . Aeson.encode $
                    object
                        [ "cardanoTxSignVault"
                            .= object
                                [ "version" .= (1 :: Int)
                                , "identities"
                                    .= object
                                        [ "bob"
                                            .= object
                                                [ "label" .= ("mallory" :: Text)
                                                , "network" .= ("preprod" :: Text)
                                                , "keyHash" .= T.replicate 56 "0"
                                                , "source" .= cliSource skey
                                                ]
                                        ]
                                ]
                        ]
            noIdentities = txSignPayloadOf 1 []
        decodeVaultPayload
            Nothing
            (txSignPayloadOf 1 [("bob", cliSource skey)])
            `shouldSatisfy` either (const False) (const True)
        forM_ [versionTwo, mislabelled] $ \payload ->
            decodeVaultPayload (Just (IdentitySelector "bob")) payload
                `shouldBe'` PayloadNotASigningKey
        decodeVaultPayload Nothing noIdentities
            `shouldSatisfy` either
                (== PayloadIdentityMissing Nothing [])
                (const False)

    it "seals a key read from a tx-sign vault as v1, never as tx-sign" $ do
        stock <- readFixture "tx-sign/vault.age"
        line <- readFixture "tx-sign/passphrase"
        let stockPassphrase = BC.takeWhile (/= '\n') line
        key <-
            either (fail . T.unpack . renderVaultRefusal) pure $
                openVault
                    (Just (IdentitySelector "bob"))
                    (passphrase stockPassphrase)
                    stock
        vault <-
            sealVault (factor 10) (passphrase "cwt interop passphrase") key
                >>= either (fail . show) pure
        (code, plaintext, _) <- ageDecrypt "cwt interop passphrase" vault
        code `shouldBe` ExitSuccess
        plaintext `shouldNotSatisfy` BS.isInfixOf "cardanoTxSignVault"
        sealedEnvelope <- either fail pure (parseEnvelope plaintext)
        bob <-
            readFixture "tx-sign/bob.skey" >>= either fail pure . parseEnvelope
        envelopeCborHex sealedEnvelope `shouldBe` envelopeCborHex bob
  where
    shouldBe' result refusal =
        result
            `shouldSatisfy` either (== refusal) (const False)
