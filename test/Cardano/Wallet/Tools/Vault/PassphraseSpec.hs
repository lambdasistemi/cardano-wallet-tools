{- |
Module      : Cardano.Wallet.Tools.Vault.PassphraseSpec
Description : Where a vault passphrase comes from, and that it stays hidden
License     : Apache-2.0

Ported from the wallet vault proofs this repository took its vault from:
the passphrase intake and the hidden terminal bracket. The terminal path
runs against a pseudo-terminal, so the echo, the prompt and the
confirmation are observed on the master end rather than assumed.
-}
module Cardano.Wallet.Tools.Vault.PassphraseSpec (spec) where

import Cardano.Wallet.Tools.Vault.Passphrase
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (SomeException, fromException, try)
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Text qualified as T
import Support.Vault
import System.IO (Handle, hFlush)
import System.Posix.IO
    ( OpenMode (ReadOnly, WriteOnly)
    , closeFd
    , defaultFileFlags
    , openFd
    )
import System.Posix.Terminal
    ( TerminalMode (MapCRtoLF)
    , TerminalState (Immediately)
    , getTerminalAttributes
    , setTerminalAttributes
    , withoutMode
    )
import System.Posix.Types (Fd (..))
import System.Timeout (timeout)
import Test.Hspec
import Test.QuickCheck
    ( Gen
    , choose
    , forAll
    , listOf1
    , property
    , vectorOf
    )

spec :: Spec
spec = describe "vault v1" $ do
    passphraseIntake
    hiddenTerminal

-- | Passphrase bytes: non-empty, any byte, line endings excluded.
genPassphraseBytes :: Gen ByteString
genPassphraseBytes =
    BS.pack
        <$> listOf1
            (choose (0, 255) `suchThatByte` (`notElem` [10, 13]))
  where
    suchThatByte gen p = do
        b <- gen
        if p b then pure b else suchThatByte gen p

-- | A distinctive passphrase no message could contain by accident.
genNeedle :: Gen ByteString
genNeedle = do
    tag <- vectorOf 24 (choose ('a', 'z'))
    pure (BC.pack ("needle-" <> tag))

passphraseIntake :: Spec
passphraseIntake = describe "passphrase intake" $ do
    it "refuses the empty passphrase" $
        mkPassphrase "" `shouldBe` Left PassphraseEmpty

    it "keeps every non-empty byte string, byte for byte" $
        property $
            forAll genPassphraseBytes $ \bytes ->
                fmap passphraseBytes (mkPassphrase bytes)
                    == Right bytes

    it "shows a fixed marker that never contains the passphrase" $
        property $
            forAll genNeedle $ \needle ->
                forAll genNeedle $ \other ->
                    let shown = show (passphrase needle)
                    in  shown == show (passphrase other)
                            && not (needle `BS.isInfixOf` BC.pack shown)

    it "confirms two agreeing lines to the passphrase" $
        confirmPassphrase "shared secret" "shared secret"
            `shouldBe` mkPassphrase "shared secret"

    it "refuses two differing lines as the confirmation mismatch" $
        confirmPassphrase "shared secret" "shared secret "
            `shouldBe` Left PassphraseConfirmationDiffers

    it "refuses an agreeing empty pair as the empty passphrase" $
        confirmPassphrase "" "" `shouldBe` Left PassphraseEmpty

    it "names the mismatch before emptiness when both apply" $
        confirmPassphrase "" "x"
            `shouldBe` Left PassphraseConfirmationDiffers

    it "reads a descriptor as one line, whatever confirmation is asked" $
        forM_ [AskOnce, AskTwice] $ \confirmation ->
            withPassphraseDescriptor "correct horse\n" $ \fd ->
                readPassphrase confirmation (PassphraseDescriptor fd)
                    `shouldReturn` mkPassphrase "correct horse"

    it "never asks a descriptor twice: a second line is not read" $
        withPassphraseDescriptor "first line\nsecond line\n" $ \fd ->
            readPassphrase AskTwice (PassphraseDescriptor fd)
                `shouldReturn` mkPassphrase "first line"

    it "trims the line ending and nothing else" $ do
        withPassphraseDescriptor "pass phrase \r\n" $ \fd ->
            readPassphrase AskOnce (PassphraseDescriptor fd)
                `shouldReturn` mkPassphrase "pass phrase "
        withPassphraseDescriptor "last line, no newline" $ \fd ->
            readPassphrase AskOnce (PassphraseDescriptor fd)
                `shouldReturn` mkPassphrase "last line, no newline"

    it "refuses an empty line on a descriptor" $
        withPassphraseDescriptor "\n" $ \fd ->
            readPassphrase AskOnce (PassphraseDescriptor fd)
                `shouldReturn` Left PassphraseEmpty

    it "names the descriptor it could not read: closed" $ do
        Fd fdn <- openFd "/dev/null" ReadOnly defaultFileFlags
        closeFd (Fd fdn)
        readPassphrase AskOnce (PassphraseDescriptor (fromIntegral fdn))
            `shouldReturn` Left
                (PassphraseDescriptorUnreadable (fromIntegral fdn))

    it "names the descriptor it could not read: no line to read" $
        withPassphraseDescriptor "" $ \fd ->
            readPassphrase AskOnce (PassphraseDescriptor fd)
                `shouldReturn` Left (PassphraseDescriptorUnreadable fd)

    it "names the descriptor it could not read: not open for reading" $ do
        Fd fdn <- openFd "/dev/null" WriteOnly defaultFileFlags
        readPassphrase AskOnce (PassphraseDescriptor (fromIntegral fdn))
            `shouldReturn` Left
                (PassphraseDescriptorUnreadable (fromIntegral fdn))

    it "renders each refusal as a line that holds no passphrase" $
        property $
            forAll genNeedle $ \needle ->
                all
                    ( \refusal ->
                        let line = renderPassphraseRefusal refusal
                        in  not (T.null line)
                                && not (BC.unpack needle `isInfixOfText` line)
                    )
                    [ PassphraseEmpty
                    , PassphraseConfirmationDiffers
                    , PassphraseDescriptorUnreadable 7
                    , PassphraseTerminalUnavailable
                    ]

    it "names the descriptor number in the unreadable refusal" $
        renderPassphraseRefusal (PassphraseDescriptorUnreadable 7)
            `shouldSatisfy` ("7" `T.isInfixOf`)
  where
    isInfixOfText needle = T.isInfixOf (T.pack needle)

hiddenTerminal :: Spec
hiddenTerminal = describe "hidden terminal" $ do
    it "holds the echo off inside the bracket, restoring it after" $
        withPseudoTerminal $ \_master _slave slaveFd -> do
            setEchoOn slaveFd
            observed <- withHiddenEcho slaveFd (echoIsOn slaveFd)
            observed `shouldBe` False
            echoIsOn slaveFd `shouldReturn` True

    it "restores the echo when the action inside the bracket fails" $
        withPseudoTerminal $ \_master _slave slaveFd -> do
            setEchoOn slaveFd
            echoInside <- newIORef Nothing
            outcome <-
                try @SomeException $
                    withHiddenEcho slaveFd $ do
                        echoIsOn slaveFd >>= writeIORef echoInside . Just
                        ioError (userError "the read fails")
            case outcome of
                Left e ->
                    fromException e
                        `shouldBe` Just (userError "the read fails")
                Right () -> expectationFailure "the failure should propagate"
            readIORef echoInside `shouldReturn` Just False
            echoIsOn slaveFd `shouldReturn` True

    it "reads a typed line, prompting, without echoing it" $
        withPseudoTerminal $ \master slave slaveFd -> do
            setEchoOn slaveFd
            finish <- atTerminal master slaveFd ["typed-secret-line"]
            result <- within (readTerminalPassphrase AskOnce slaveFd slave)
            result `shouldBe` mkPassphrase "typed-secret-line"
            session <- finish
            sessionPrompts session `shouldBe` [False]
            sessionTranscript session `shouldSatisfy` not . BS.null
            sessionTranscript session
                `shouldSatisfy` not . BS.isInfixOf "typed-secret-line"
            echoIsOn slaveFd `shouldReturn` True

    it "echoes the same typed line when the echo is left on (control)" $
        withPseudoTerminal $ \master slave slaveFd -> do
            setEchoOn slaveFd
            BS.hPut master "typed-secret-line\n" >> hFlush master
            line <- within (BC.hGetLine slave)
            line `shouldSatisfy` BS.isPrefixOf "typed-secret-line"
            shown <- drain master
            shown `shouldSatisfy` BS.isInfixOf "typed-secret-line"

    it "asks twice on creation and accepts two agreeing lines" $
        withPseudoTerminal $ \master slave slaveFd -> do
            setEchoOn slaveFd
            finish <- atTerminal master slaveFd ["agreeing line", "agreeing line"]
            result <- within (readTerminalPassphrase AskTwice slaveFd slave)
            result `shouldBe` mkPassphrase "agreeing line"
            session <- finish
            sessionPrompts session `shouldBe` [False, False]
            echoIsOn slaveFd `shouldReturn` True

    it "asks twice on creation and refuses two differing lines" $
        withPseudoTerminal $ \master slave slaveFd -> do
            setEchoOn slaveFd
            finish <- atTerminal master slaveFd ["first line", "second line"]
            result <- within (readTerminalPassphrase AskTwice slaveFd slave)
            result `shouldBe` Left PassphraseConfirmationDiffers
            session <- finish
            sessionPrompts session `shouldBe` [False, False]
            echoIsOn slaveFd `shouldReturn` True

    it
        "trims the carriage return of a terminal that does not translate it"
        $ withPseudoTerminal
        $ \master slave slaveFd -> do
            attributes <- getTerminalAttributes slaveFd
            setTerminalAttributes
                slaveFd
                (withoutMode attributes MapCRtoLF)
                Immediately
            finish <- atTerminal master slaveFd ["typed-with-cr\r"]
            result <- within (readTerminalPassphrase AskOnce slaveFd slave)
            result `shouldBe` mkPassphrase "typed-with-cr"
            _ <- finish
            pure ()

    it "asks once on opening: one prompt, one line" $
        withPseudoTerminal $ \master slave slaveFd -> do
            finish <- atTerminal master slaveFd ["only line"]
            result <- within (readTerminalPassphrase AskOnce slaveFd slave)
            result `shouldBe` mkPassphrase "only line"
            session <- finish
            length (sessionPrompts session) `shouldBe` 1

    it "refuses an empty typed line, on opening and on creation" $ do
        withPseudoTerminal $ \master slave slaveFd -> do
            finish <- atTerminal master slaveFd [""]
            result <- within (readTerminalPassphrase AskOnce slaveFd slave)
            result `shouldBe` Left PassphraseEmpty
            _ <- finish
            pure ()
        withPseudoTerminal $ \master slave slaveFd -> do
            finish <- atTerminal master slaveFd ["", ""]
            result <- within (readTerminalPassphrase AskTwice slaveFd slave)
            result `shouldBe` Left PassphraseEmpty
            _ <- finish
            pure ()

-- | What a simulated user at the terminal saw and found.
data Session = Session
    { sessionTranscript :: ByteString
    -- ^ everything the terminal printed
    , sessionPrompts :: [Bool]
    -- ^ whether the echo was on, at each prompt, before the line was typed
    }

{- | A user at the terminal: after each prompt reaches the master end,
note whether the echo is on, then type the next line. The returned
action waits for the user and gives the session; a prompt that never
comes ends the session in failure rather than typing blind.
-}
atTerminal :: Handle -> Fd -> [ByteString] -> IO (IO Session)
atTerminal master slaveFd typed = do
    done <- newEmptyMVar
    _ <- forkIO $ do
        outcome <- try (user typed mempty [])
        putMVar done outcome
    pure $ do
        outcome <- within (takeMVar done)
        case outcome of
            Left (e :: SomeException) ->
                fail ("the simulated user failed: " <> show e)
            Right session -> do
                rest <- drain master
                pure session{sessionTranscript = sessionTranscript session <> rest}
  where
    user [] seen prompts = pure (Session seen (reverse prompts))
    user (line : more) seen prompts = do
        prompt <- awaitOutput master
        echoing <- echoIsOn slaveFd
        BS.hPut master (line <> "\n") >> hFlush master
        user more (seen <> prompt) (echoing : prompts)

-- | The next output on the master end; no output in time is a failure.
awaitOutput :: Handle -> IO ByteString
awaitOutput master = go (1000 :: Int)
  where
    go 0 = ioError (userError "no prompt reached the terminal")
    go n = do
        out <- drain master
        if BS.null out then threadDelay 5000 >> go (n - 1) else pure out

-- | A hang guard, not a timing assertion: the example fails, not stalls.
within :: IO a -> IO a
within action =
    timeout 60000000 action
        >>= maybe (fail "the terminal exchange stalled") pure
