{- |
Module      : Cardano.Wallet.Tools.Cli.VaultSpec
Description : The cwt vault commands: flags and handlers
License     : Apache-2.0

What an operator of @cwt@ can say and what comes back. The flags are
parsed by the library's own parsers; the handlers run against real
files and inherited descriptors. The passphrase has two sources only, a
terminal and @--passphrase-fd@: a file, an environment variable or an
argument is a parse failure.
-}
module Cardano.Wallet.Tools.Cli.VaultSpec (spec) where

import Cardano.Wallet.Tools.Cli.Vault
import Cardano.Wallet.Tools.Sign
    ( DetachedWitness (..)
    , Signer
    )
import Cardano.Wallet.Tools.Vault.File
    ( VaultRefusal (..)
    , renderVaultRefusal
    )
import Cardano.Wallet.Tools.Vault.Passphrase (PassphraseSource (..))
import Cardano.Wallet.Tools.Vault.Payload (IdentitySelector (..))
import Cardano.Wallet.Tools.Vault.Scrypt (vaultWorkFactorCap)
import Control.Monad (forM_, void)
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Either (lefts)
import Data.List (isInfixOf)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Support.Vault
import System.Directory (doesPathExist)
import System.FilePath ((</>))
import System.Posix.Files (fileMode, getFileStatus)
import Test.Hspec
import Test.QuickCheck (forAll, ioProperty, property, withMaxSuccess)
import Test.QuickCheck qualified as QC

spec :: Spec
spec = describe "vault v1" $ do
    describe "command line" $ do
        parsing
        handlers
    capAtTheCommandLine

-- * Parsing

parsing :: Spec
parsing = do
    describe "signing key source" $ do
        it "takes a plaintext key file" $
            parseArgs signingKeySourceParser ["--signing-key", "k.skey"]
                `shouldBe` Right (PlaintextKey "k.skey")

        it "takes a vault, asking on the terminal by default" $
            parseArgs signingKeySourceParser ["--signing-key-vault", "v.age"]
                `shouldBe` Right (VaultKey "v.age" PassphraseTerminal Nothing)

        it "takes the passphrase from a descriptor" $
            parseArgs
                signingKeySourceParser
                ["--signing-key-vault", "v.age", "--passphrase-fd", "9"]
                `shouldBe` Right (VaultKey "v.age" (PassphraseDescriptor 9) Nothing)

        it "takes an identity of a tx-sign vault by label" $
            parseArgs
                signingKeySourceParser
                [ "--signing-key-vault"
                , "v.age"
                , "--passphrase-fd"
                , "3"
                , "--vault-identity"
                , "alice"
                ]
                `shouldBe` Right
                    ( VaultKey
                        "v.age"
                        (PassphraseDescriptor 3)
                        (Just (IdentitySelector "alice"))
                    )

        it "has no other source for the passphrase"
            $ forM_
                [ ["--signing-key-vault", "v.age", "--passphrase-file", "p"]
                , ["--signing-key-vault", "v.age", "--passphrase", "hunter2"]
                , ["--signing-key-vault", "v.age", "--passphrase-env", "PP"]
                ]
            $ \args ->
                parseArgs signingKeySourceParser args
                    `shouldSatisfy` either (const True) (const False)

        it "refuses a descriptor that is not a descriptor number" $
            forM_ ["x", "-1", "1.5", ""] $ \bad ->
                parseArgs
                    signingKeySourceParser
                    ["--signing-key-vault", "v.age", "--passphrase-fd", bad]
                    `shouldSatisfy` either (const True) (const False)

        it "refuses a passphrase or an identity beside a plaintext key"
            $ forM_
                [ ["--signing-key", "k", "--passphrase-fd", "3"]
                , ["--signing-key", "k", "--vault-identity", "alice"]
                ]
            $ \args ->
                parseArgs signingKeySourceParser args
                    `shouldSatisfy` either (const True) (const False)

        it "refuses no source at all" $
            parseArgs signingKeySourceParser []
                `shouldSatisfy` either (const True) (const False)

    describe "vault seal" $ do
        let sealBase = ["--signing-key", "k.skey", "--out", "v.age"]
        it "seals with a terminal passphrase at the cap by default" $
            parseArgs vaultSealParser sealBase
                `shouldBe` Right
                    ( VaultSealOptions
                        "k.skey"
                        "v.age"
                        PassphraseTerminal
                        vaultWorkFactorCap
                    )

        it "takes the passphrase from a descriptor and a work factor" $
            parseArgs
                vaultSealParser
                (sealBase <> ["--passphrase-fd", "4", "--work-factor", "12"])
                `shouldBe` Right
                    ( VaultSealOptions
                        "k.skey"
                        "v.age"
                        (PassphraseDescriptor 4)
                        (factor 12)
                    )

        it "accepts every work factor from 1 to the cap" $
            forM_ [1, 17, 18] $ \n ->
                fmap
                    sealWorkFactor
                    (parseArgs vaultSealParser (sealBase <> ["--work-factor", show n]))
                    `shouldBe` Right (factor n)

        it "refuses a work factor outside 1 to the cap" $
            forM_ ["0", "19", "255", "-1", "x", "10.5"] $ \bad ->
                parseArgs vaultSealParser (sealBase <> ["--work-factor", bad])
                    `shouldSatisfy` either (const True) (const False)

        it "names the cap when it refuses a work factor above it" $
            parseArgs vaultSealParser (sealBase <> ["--work-factor", "19"])
                `shouldSatisfy` either ("to 18" `isInfixOf`) (const False)

        it "refuses a missing key or output, and any passphrase file"
            $ forM_
                [ ["--out", "v.age"]
                , ["--signing-key", "k.skey"]
                , sealBase <> ["--passphrase-file", "p"]
                , sealBase <> ["--passphrase", "hunter2"]
                ]
            $ \args ->
                parseArgs vaultSealParser args
                    `shouldSatisfy` either (const True) (const False)

-- * Handlers

handlers :: Spec
handlers = do
    describe "cwt vault seal, then cwt sign" $ do
        it "signs with the key it sealed" $
            withTempDir "cli" $ \dir -> do
                vkey <- verificationKeyOfFixture "payment.vkey"
                let out = dir </> "payment.age"
                sealTo out "cwt cli passphrase" ["--work-factor", "10"]
                    `shouldReturn` Right ()
                signer <- signerFromVaultFile out "cwt cli passphrase" Nothing
                witness <- witnessOf signer "body"
                signatureVerifies
                    vkey
                    (bodyHash "body")
                    (detachedWitnessSignature witness)
                    `shouldBe` True
                mode <- fileMode <$> getFileStatus out
                (mode .&. 0o777) `shouldBe` 0o600

        it "refuses a wrong passphrase with the opening refusal" $
            withTempDir "cli" $ \dir -> do
                let out = dir </> "payment.age"
                sealTo out "cwt cli passphrase" ["--work-factor", "10"]
                    `shouldReturn` Right ()
                outcome <- loadFrom out "another passphrase" Nothing
                outcome `shouldBe` Left (renderVaultRefusal VaultNotOpened)

    describe "signing key file" $ do
        it "signs with a plaintext cardano-cli key" $ do
            vkey <- verificationKeyOfFixture "payment.vkey"
            outcome <-
                loadSignerFromSource (PlaintextKey (fixturePath "payment.skey"))
            signer <- either (fail . T.unpack) pure outcome
            witness <- witnessOf signer "body"
            detachedWitnessVKey witness `shouldBe` vkey

        it "refuses what is not a signing key, or not there, in one line" $ do
            forM_
                [ fixturePath "payment.vkey"
                , fixturePath "tx-sign/payload.json"
                , fixturePath "does-not-exist"
                ]
                $ \path -> do
                    outcome <- loadSignerFromSource (PlaintextKey path)
                    refusalOf outcome `shouldSatisfy` maybe False (not . T.null)

    describe "tx-sign vault" $ do
        it "signs as the identity chosen by label" $ do
            labels <-
                readFixture "tx-sign/payload.json" >>= identityLabelsOfPayload
            forM_ labels $ \label -> do
                vkey <-
                    verificationKeyOfFixture ("tx-sign/" <> T.unpack label <> ".vkey")
                outcome <-
                    withDescriptorOn (fixturePath "tx-sign/passphrase") $ \fd ->
                        loadSignerFromSource
                            ( VaultKey
                                (fixturePath "tx-sign/vault.age")
                                (PassphraseDescriptor fd)
                                (Just (IdentitySelector label))
                            )
                signer <- either (fail . T.unpack) pure outcome
                witness <- witnessOf signer "body"
                detachedWitnessVKey witness `shouldBe` vkey

        it "names the labels when several identities and no choice" $ do
            labels <-
                readFixture "tx-sign/payload.json" >>= identityLabelsOfPayload
            outcome <-
                withDescriptorOn (fixturePath "tx-sign/passphrase") $ \fd ->
                    loadSignerFromSource
                        ( VaultKey
                            (fixturePath "tx-sign/vault.age")
                            (PassphraseDescriptor fd)
                            Nothing
                        )
            case outcome of
                Left line -> forM_ labels $ \label -> line `shouldSatisfy` T.isInfixOf label
                Right _ -> expectationFailure "several identities opened without a choice"

    describe "sealing refuses" $ do
        it "an input that is not a signing key, before creating the vault" $
            withTempDir "cli" $ \dir -> do
                forM_
                    [ fixturePath "payment.vkey"
                    , fixturePath "tx-sign/payload.json"
                    , fixturePath "PROVENANCE.md"
                    , dir </> "no-such-key"
                    ]
                    $ \input -> do
                        let out = dir </> "refused.age"
                        sealFrom input out "pass" []
                            >>= (`shouldSatisfy` either (not . T.null) (const False))
                        doesPathExist out `shouldReturn` False

        it "an existing vault path, leaving it as it was" $
            withTempDir "cli" $ \dir -> do
                let out = dir </> "payment.age"
                BS.writeFile out "an existing wallet"
                sealTo out "pass" ["--work-factor", "10"]
                    >>= (`shouldSatisfy` either (T.isInfixOf (T.pack out)) (const False))
                BS.readFile out `shouldReturn` "an existing wallet"

        it "an empty passphrase, creating nothing" $
            withTempDir "cli" $ \dir -> do
                let out = dir </> "payment.age"
                sealTo out "" ["--work-factor", "10"]
                    >>= (`shouldSatisfy` either (not . T.null) (const False))
                doesPathExist out `shouldReturn` False

        it "an unreadable passphrase descriptor, creating nothing" $
            withTempDir "cli" $ \dir -> do
                let out = dir </> "payment.age"
                options <-
                    either fail pure $
                        parseArgs
                            vaultSealParser
                            [ "--signing-key"
                            , fixturePath "payment.skey"
                            , "--out"
                            , out
                            , "--passphrase-fd"
                            , "999"
                            ]
                runVaultSeal options
                    >>= (`shouldSatisfy` either (T.isInfixOf "999") (const False))
                doesPathExist out `shouldReturn` False

    describe "passphrase source" $
        it "ignores environment variables that look like a passphrase" $
            withTempDir "cli" $ \dir -> do
                let out = dir </> "payment.age"
                    right = "the right passphrase"
                sealTo out right ["--work-factor", "10"] `shouldReturn` Right ()
                withEnv
                    [ (name, BC.unpack right)
                    | name <-
                        [ "AGE_PASSPHRASE"
                        , "CWT_PASSPHRASE"
                        , "CWT_VAULT_PASSPHRASE"
                        , "VAULT_PASSPHRASE"
                        , "PASSPHRASE"
                        ]
                    ]
                    (loadFrom out "a wrong passphrase" Nothing)
                    `shouldReturn` Left (renderVaultRefusal VaultNotOpened)

    describe "no message holds the passphrase" $
        it "whatever the passphrase, no refusal repeats it" $
            withMaxSuccess 10 $
                property $
                    forAll genNeedle $ \needle -> ioProperty $
                        withTempDir "cli" $ \dir -> do
                            let out = dir </> "payment.age"
                                quick = ["--work-factor", "1"]
                            notAKey <- sealFrom (fixturePath "payment.vkey") out needle quick
                            sealTo out needle quick `shouldReturn` Right ()
                            existing <- sealTo out needle quick
                            wrong <- loadFrom out (needle <> "!") Nothing
                            let texts = lefts [notAKey, existing, wrong]
                            pure $
                                length texts == 3
                                    && not (any (T.isInfixOf (TE.decodeUtf8 needle)) texts)

-- * Work factor cap, at the command

capAtTheCommandLine :: Spec
capAtTheCommandLine = describe "work factor cap" $ do
    it "refuses, at cwt sign, a vault above the cap" $
        withTempDir "cap" $ \dir -> do
            skey <- readFixture "payment.skey"
            let at19 = dir </> "above.age"
                at10 = dir </> "within.age"
            BS.writeFile at19 =<< encryptAtFactor 19 "pass" skey
            BS.writeFile at10 =<< encryptAtFactor 10 "pass" skey
            vkey <- verificationKeyOfFixture "payment.vkey"
            within10 <- loadFrom at10 "pass" Nothing
            within10 `shouldSatisfy` either (const False) (const True)
            signer <- signerFromVaultFile at10 "pass" Nothing
            witnessOf signer "body"
                >>= (`shouldSatisfy` ((== vkey) . detachedWitnessVKey))
            above <- loadFrom at19 "pass" Nothing
            above `shouldBe` Left (renderVaultRefusal VaultNotOpened)

    it "answers a wrong passphrase and an above-cap vault alike" $
        withTempDir "cap" $ \dir -> do
            skey <- readFixture "payment.skey"
            let above = dir </> "above.age"
                within' = dir </> "within.age"
            BS.writeFile above =<< encryptAtFactor 19 "pass" skey
            BS.writeFile within' =<< encryptAtFactor 10 "pass" skey
            overCap <- loadFrom above "pass" Nothing
            wrongPass <- loadFrom within' "not the passphrase" Nothing
            overCap `shouldBe` wrongPass
            overCap `shouldSatisfy` either (not . T.null) (const False)

-- * Helpers

genNeedle :: QC.Gen ByteString
genNeedle = do
    tag <- QC.vectorOf 24 (QC.choose ('a', 'z'))
    pure (BC.pack ("needle-" <> tag))

ignoreSigner :: Either Text (Signer IO) -> Either Text ()
ignoreSigner = void

refusalOf :: Either Text a -> Maybe Text
refusalOf = either Just (const Nothing)

-- | Seal a key file to a vault path, the passphrase on a descriptor.
sealFrom
    :: FilePath -> FilePath -> ByteString -> [String] -> IO (Either Text ())
sealFrom input out secret extra =
    withPassphraseDescriptor (secret <> "\n") $ \fd -> do
        options <-
            either fail pure $
                parseArgs
                    vaultSealParser
                    ( [ "--signing-key"
                      , input
                      , "--out"
                      , out
                      , "--passphrase-fd"
                      , show fd
                      ]
                        <> extra
                    )
        runVaultSeal options

sealTo :: FilePath -> ByteString -> [String] -> IO (Either Text ())
sealTo = sealFrom (fixturePath "payment.skey")

-- | Load a signer from a vault, the passphrase on a descriptor.
loadFrom
    :: FilePath
    -> ByteString
    -> Maybe IdentitySelector
    -> IO (Either Text ())
loadFrom path secret selector =
    withPassphraseDescriptor (secret <> "\n") $ \fd ->
        ignoreSigner
            <$> loadSignerFromSource
                (VaultKey path (PassphraseDescriptor fd) selector)
