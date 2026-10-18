{- |
Module      : Cardano.Wallet.Tools.Vault.TxSignIdentitySpec
Description : tx-sign identities: addr_xsk sources and the stored key hash
License     : Apache-2.0

A @cardano-tx-tools@ @tx-sign vault@ identity is read whichever source
it carries, and is read only if the key hash it stores is the key's.

The vaults were made by @tx-sign vault create@ and decrypt with stock
@age@; the key hashes, the verification keys and the witnesses the
specs compare with were produced by @cardano-tx-tools@ and
@cardano-cli@, and are read from the fixture files at run time. The
signature check is crypton's. None of it calls the library under test.
-}
module Cardano.Wallet.Tools.Vault.TxSignIdentitySpec (spec) where

import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , Signer (..)
    , TxBodyBytes (..)
    , decodeDetachedWitness
    , encodeDetachedWitness
    , transactionBodyBytes
    )
import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase (Passphrase)
import Cardano.Wallet.Tools.Vault.Payload
import Cardano.Wallet.Tools.Vault.Scrypt (openVault)
import Codec.Binary.Bech32 qualified as Bech32
import Control.Monad (forM, forM_)
import Data.Aeson (Value (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as B16
import Data.ByteString.Char8 qualified as BC
import Data.Functor (void)
import Data.List (nub)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.Vault
import System.Exit (ExitCode (..))
import Test.Hspec
import Test.QuickCheck (forAll, ioProperty, property)
import Test.QuickCheck qualified as QC

spec :: Spec
spec = describe "vault v1" $ do
    addrXsk
    keyHashCheck
    goldenVaults

-- * Fixtures

-- | A tx-sign vault of the fixtures: its bytes, its payload and its identity.
data Golden = Golden
    { goldenVault :: ByteString
    , goldenPayload :: ByteString
    , goldenLabel :: Text
    , goldenKeyHash :: Text
    }

golden :: String -> IO Golden
golden name = do
    vault <- readFixture ("golden/" <> name <> ".vault.age")
    payload <- readFixture ("golden/" <> name <> ".payload.json")
    keyHashesOfPayload payload >>= \case
        [(label, hash)] -> pure (Golden vault payload label hash)
        other -> fail ("not one identity: " <> show (length other))

goldenPassphrase :: IO Passphrase
goldenPassphrase = passphrase <$> readPassphraseFixture "golden/passphrase"

-- | The key a tx-sign vault opens to; the refusal, rendered, fails the example.
opened :: Maybe IdentitySelector -> Golden -> IO OpenedKey
opened selector g = do
    pass <- goldenPassphrase
    either (fail . T.unpack . renderVaultRefusal) pure $
        openVault selector pass (goldenVault g)

-- | The identity of a vault, chosen by its label.
byLabel :: Golden -> Maybe IdentitySelector
byLabel = Just . IdentitySelector . goldenLabel

-- | The witness the fixture file holds, with its verification key.
witnessFixture :: FilePath -> IO DetachedWitness
witnessFixture name =
    readHexFixture name
        >>= either (fail . show) pure . decodeDetachedWitness

-- | The body bytes of a fixture transaction.
bodyFixture :: FilePath -> IO TxBodyBytes
bodyFixture name =
    readHexFixture name
        >>= either (fail . show) pure . transactionBodyBytes

-- | The verification key a key signs under.
vkeyOf :: OpenedKey -> IO ByteString
vkeyOf key = detachedWitnessVKey <$> witnessOf (signerFromKey key) "a body"

-- | A hex rendering, as a vault stores a key hash.
hexText :: ByteString -> Text
hexText = TE.decodeUtf8 . B16.encode

-- | A body of any size, empty included.
genBody :: QC.Gen ByteString
genBody = BS.pack <$> QC.listOf (QC.choose (0, 255))

-- | The text and the bytes of the addr_xsk a payload stores for a label.
storedXsk :: Text -> ByteString -> IO (Text, ByteString)
storedXsk label payload = do
    text <- sourceFieldOfPayload label "bech32" payload
    (_, dataPart) <- either (fail . show) pure (Bech32.decodeLenient text)
    bytes <-
        maybe (fail "the stored addr_xsk is not bech32 bytes") pure $
            Bech32.dataPartToBytes dataPart
    pure (text, bytes)

-- * addr_xsk

addrXsk :: Spec
addrXsk = describe "tx-sign addr_xsk" $ do
    it "opens the identity of a vault made by cardano-tx-tools" $ do
        g <- golden "xsk"
        chosen <- opened (byLabel g) g
        only <- opened Nothing g
        a <- witnessOf (signerFromKey chosen) "a body"
        b <- witnessOf (signerFromKey only) "a body"
        a `shouldBe` b

    it "has a golden witness that verifies over the body hash (control)" $ do
        expected <- witnessFixture "golden/xsk-witness.expected.hex"
        TxBodyBytes body <- bodyFixture "golden/xsk-unsigned.cbor.hex"
        let vkey = detachedWitnessVKey expected
            signature = detachedWitnessSignature expected
        signatureVerifies vkey (bodyHash body) signature `shouldBe` True
        signatureVerifies vkey body signature `shouldBe` False

    it "signs as the verification key cardano-tx-tools derived" $ do
        g <- golden "xsk"
        key <- opened (byLabel g) g
        expected <- witnessFixture "golden/xsk-witness.expected.hex"
        TxBodyBytes body <- bodyFixture "golden/xsk-unsigned.cbor.hex"
        witness <- witnessOf (signerFromKey key) body
        detachedWitnessVKey witness `shouldBe` detachedWitnessVKey expected
        detachedWitnessSignature witness
            `shouldSatisfy` signatureVerifies
                (detachedWitnessVKey expected)
                (bodyHash body)

    it "gives the witness cardano-tx-tools made for the same body" $ do
        g <- golden "xsk"
        key <- opened (byLabel g) g
        expected <- witnessFixture "golden/xsk-witness.expected.hex"
        TxBodyBytes body <- bodyFixture "golden/xsk-unsigned.cbor.hex"
        witness <- witnessOf (signerFromKey key) body
        encodeDetachedWitness witness
            `shouldBe` encodeDetachedWitness expected

    it "gives the same witness through the loader of cwt sign" $ do
        g <- golden "xsk"
        secret <- readPassphraseFixture "golden/passphrase"
        signer <-
            signerFromVaultFile
                (fixturePath "golden/xsk.vault.age")
                secret
                (byLabel g)
        expected <- witnessFixture "golden/xsk-witness.expected.hex"
        body <- bodyFixture "golden/xsk-unsigned.cbor.hex"
        witness <- signTxBody signer body
        encodeDetachedWitness witness
            `shouldBe` encodeDetachedWitness expected

    beforeAll xskKeyAndVKey $
        it "signs the hash of any body under its verification key" $
            \(key, vkey) ->
                property $
                    forAll genBody $ \body -> ioProperty $ do
                        witness <- witnessOf (signerFromKey key) body
                        let signature = detachedWitnessSignature witness
                        pure $
                            detachedWitnessVKey witness == vkey
                                && signatureVerifies vkey (bodyHash body) signature
                                && not (signatureVerifies vkey body signature)

    it "refuses key material that is not a 96-byte addr_xsk, as not a key" $ do
        g <- golden "xsk"
        (stored, bytes) <- storedXsk (goldenLabel g) (goldenPayload g)
        xsk <- hrp "addr_xsk"
        xvk <- hrp "addr_xvk"
        let reencoded part body =
                Bech32.encodeLenient part (Bech32.dataPartFromBytes body)
            variants :: [(String, Text)]
            variants =
                [ ("a damaged checksum", damaged stored)
                , ("another human-readable part", reencoded xvk bytes)
                , ("a key without its chain code", reencoded xsk (BS.take 64 bytes))
                , ("a key with a longer tail", reencoded xsk (bytes <> "x"))
                , ("not bech32", "this is not bech32")
                , ("nothing", "")
                ]
            decoded bech32 =
                void . decodeVaultPayload (byLabel g) $
                    payloadWithSourceField
                        (goldenLabel g)
                        "bech32"
                        (String bech32)
                        (goldenPayload g)
        decoded stored `shouldBe` Right ()
        [ what | (what, bech32) <- variants, decoded bech32 /= Left PayloadNotASigningKey
            ]
            `shouldBe` []

    it "shows no byte of the key" $ do
        g <- golden "xsk"
        key <- opened Nothing g
        (stored, bytes) <- storedXsk (goldenLabel g) (goldenPayload g)
        let shown = BC.pack (show key)
        shown `shouldNotSatisfy` BS.isInfixOf (TE.encodeUtf8 stored)
        shown `shouldNotSatisfy` BS.isInfixOf (B16.encode bytes)
        shown `shouldNotSatisfy` BS.isInfixOf (B16.encode (BS.take 32 bytes))

    it "is chosen by label beside a cardano-cli identity of one payload" $ do
        xsk <- golden "xsk"
        cli <- golden "cli"
        let payload = mergedPayload [goldenPayload cli, goldenPayload xsk]
        cliVKey <-
            detachedWitnessVKey
                <$> witnessFixture "golden/witness.expected.hex"
        xskVKey <-
            detachedWitnessVKey
                <$> witnessFixture "golden/xsk-witness.expected.hex"
        forM_ [(xsk, xskVKey), (cli, cliVKey)] $ \(g, vkey) -> do
            key <-
                either (fail . show) pure $
                    decodeVaultPayload (byLabel g) payload
            vkeyOf key `shouldReturn` vkey
        case decodeVaultPayload Nothing payload of
            Left (PayloadIdentityMissing Nothing named) ->
                named `shouldMatchList` [goldenLabel cli, goldenLabel xsk]
            other ->
                expectationFailure
                    ("not refused by name: " <> show (void other))
  where
    xskKeyAndVKey = do
        g <- golden "xsk"
        key <- opened Nothing g
        vkey <-
            detachedWitnessVKey
                <$> witnessFixture "golden/xsk-witness.expected.hex"
        pure (key, vkey)
    hrp name =
        either (fail . show) pure (Bech32.humanReadablePartFromText name)

-- | The same text with its last character changed.
damaged :: Text -> Text
damaged text =
    T.init text
        <> T.singleton (if T.last text == 'q' then 'p' else 'q')

-- * The stored key hash

keyHashCheck :: Spec
keyHashCheck = describe "tx-sign key hash" $ do
    it "is blake2b-224 of the verification key in every fixture (control)" $ do
        payload <- readFixture "tx-sign/payload.json"
        stored <- keyHashesOfPayload payload
        length stored `shouldSatisfy` (> 2)
        forM_ stored $ \(label, hash) -> do
            vkey <-
                verificationKeyOfFixture
                    ("tx-sign/" <> T.unpack label <> ".vkey")
            (label, hash) `shouldBe` (label, hexText (keyHashOf vkey))
        forM_
            [ ("cli", "golden/witness.expected.hex")
            , ("xsk", "golden/xsk-witness.expected.hex")
            ]
            $ \(name, witnessFile) -> do
                g <- golden name
                vkey <- detachedWitnessVKey <$> witnessFixture witnessFile
                goldenKeyHash g `shouldBe` hexText (keyHashOf vkey)
        alice <- verificationKeyOfFixture "tx-sign/alice.vkey"
        bob <- verificationKeyOfFixture "tx-sign/bob.vkey"
        keyHashOf alice `shouldNotBe` keyHashOf bob

    it "lets through the identities of the vaults cardano-tx-tools made" $
        forM_ ["cli", "xsk"] $ \name -> do
            g <- golden name
            key <- opened (byLabel g) g
            _ <- witnessOf (signerFromKey key) "a body"
            pure ()

    it "refuses an identity that stores another key's hash, naming it" $ do
        payload <- readFixture "tx-sign/payload.json"
        stored <- keyHashesOfPayload payload
        let pairs =
                [ (label, otherHash)
                | (label, _) <- stored
                , (other, otherHash) <- stored
                , other /= label
                ]
        length pairs `shouldSatisfy` (> 2)
        faults <- forM pairs $ \(label, otherHash) -> do
            secrets <- keyMaterialOfFixture label
            pure $
                keyHashRefusalFaults
                    (label, secrets)
                    ( decodeVaultPayload
                        (Just (IdentitySelector label))
                        (payloadWithKeyHash label otherHash payload)
                    )
        concat faults `shouldBe` []

    it "refuses it through a stock age vault, for either source kind"
        $ forM_
            [
                ( "cli-mismatched"
                , "golden/payment.skey"
                , "golden/witness.expected.hex"
                )
            ,
                ( "xsk-mismatched"
                , "golden/payment.addr_xsk"
                , "golden/xsk-witness.expected.hex"
                )
            ]
        $ \(name, keyFile, witnessFile) -> do
            g <- golden name
            pass <- goldenPassphrase
            key <- readFixture keyFile
            vkey <- detachedWitnessVKey <$> witnessFixture witnessFile
            case openVault (byLabel g) pass (goldenVault g) of
                Left refusal@(VaultPayloadRefused payloadRefusal) -> do
                    let line = renderVaultRefusal refusal
                    line `shouldSatisfy` T.isInfixOf (goldenLabel g)
                    T.toLower line `shouldSatisfy` T.isInfixOf "key hash"
                    BC.pack (show refusal)
                        `shouldNotSatisfy` BS.isInfixOf key
                    TE.encodeUtf8 line `shouldNotSatisfy` BS.isInfixOf key
                    line `shouldNotSatisfy` T.isInfixOf (hexText vkey)
                    payloadRefusal `shouldNotBe` PayloadNotASigningKey
                other ->
                    expectationFailure
                        ("not refused as a key hash mismatch: " <> show (void other))

    it "refuses a stored value that is not the key's hash" $ do
        payload <- readFixture "tx-sign/payload.json"
        stored <- keyHashesOfPayload payload
        true <- hashOf "bob" stored
        let variants =
                [ ("empty", "")
                , ("not hex", "zz")
                , ("an odd number of digits", T.take 55 true)
                , ("longer than a key hash", true <> "00")
                , ("zeros", T.replicate 56 "0")
                , ("one digit off", T.init true <> otherDigit (T.last true))
                ]
        secrets <- keyMaterialOfFixture "bob"
        [ what <> ": " <> fault
            | (what, hash) <- variants
            , fault <-
                keyHashRefusalFaults
                    ("bob", secrets)
                    ( decodeVaultPayload
                        (Just (IdentitySelector "bob"))
                        (payloadWithKeyHash "bob" hash payload)
                    )
            ]
            `shouldBe` []

    it "checks the identity it opens and no other" $ do
        payload <- readFixture "tx-sign/payload.json"
        stored <- keyHashesOfPayload payload
        bobHash <- hashOf "bob" stored
        let tampered = payloadWithKeyHash "alice" bobHash payload
        bob <- verificationKeyOfFixture "tx-sign/bob.vkey"
        key <-
            either (fail . show) pure $
                decodeVaultPayload (Just (IdentitySelector "bob")) tampered
        vkeyOf key `shouldReturn` bob
        secrets <- keyMaterialOfFixture "alice"
        keyHashRefusalFaults
            ("alice", secrets)
            (decodeVaultPayload (Just (IdentitySelector "alice")) tampered)
            `shouldBe` []

    it "checks the only identity of a payload when none is chosen" $ do
        payload <- readFixture "tx-sign/payload.json"
        stored <- keyHashesOfPayload payload
        aliceHash <- hashOf "alice" stored
        let single = payloadKeeping ["bob"] payload
        decodeVaultPayload Nothing single
            `shouldSatisfy` either (const False) (const True)
        secrets <- keyMaterialOfFixture "bob"
        keyHashRefusalFaults
            ("bob", secrets)
            ( decodeVaultPayload Nothing (payloadWithKeyHash "bob" aliceHash single)
            )
            `shouldBe` []
  where
    hashOf label stored =
        maybe
            (fail ("no identity " <> T.unpack label))
            pure
            (lookup label stored)
    otherDigit c = T.singleton (if c == '0' then '1' else '0')

{- | The secret and verification key bytes of a fixture identity, which
no refusal may carry.
-}
keyMaterialOfFixture :: Text -> IO [ByteString]
keyMaterialOfFixture label = do
    secret <-
        verificationKeyOfFixture ("tx-sign/" <> T.unpack label <> ".skey")
    vkey <-
        verificationKeyOfFixture ("tx-sign/" <> T.unpack label <> ".vkey")
    pure [secret, vkey]

{- | What is wrong with an outcome that should be the key-hash refusal
of an identity: it names the label, says key hash, and carries none of
the key bytes. Nothing is wrong when the list is empty.
-}
keyHashRefusalFaults
    :: (Show a)
    => (Text, [ByteString])
    -> Either VaultPayloadRefusal a
    -> [String]
keyHashRefusalFaults (label, material) = \case
    Right opened' -> ["the identity opened: " <> show opened']
    Left refusal ->
        let line = renderVaultPayloadRefusal refusal
        in  [ "does not name " <> T.unpack label
            | not (label `T.isInfixOf` line)
            ]
                <> [ "does not say key hash: " <> T.unpack line
                   | not ("key hash" `T.isInfixOf` T.toLower line)
                   ]
                <> [ "carries key bytes"
                   | bytes <- material
                   , hexText bytes `T.isInfixOf` line
                        || B16.encode bytes `BS.isInfixOf` BC.pack (show refusal)
                   ]

-- * The fixtures themselves

goldenVaults :: Spec
goldenVaults = describe "tx-sign fixtures" $
    it "keep each payload beside the vault stock age opens to it" $ do
        secret <- readPassphraseFixture "golden/passphrase"
        let names = ["cli", "xsk", "cli-mismatched", "xsk-mismatched"]
        payloads <- forM names $ \name -> do
            g <- golden name
            (code, plaintext, _) <- ageDecrypt secret (goldenVault g)
            pure (name, code, plaintext, goldenPayload g)
        [ name
            | (name, code, plaintext, payload) <- payloads
            , code /= ExitSuccess || plaintext /= payload
            ]
            `shouldBe` []
        let distinct = [payload | (_, _, _, payload) <- payloads]
        length (nub distinct) `shouldBe` length distinct
