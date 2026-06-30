{- |
Module      : Cardano.Wallet.Tools.Sign.AttachWitness
Description : Body-preserving detached witness attachment.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Pure CBOR-level helpers for extracting transaction-body bytes and
splicing detached vkey witnesses into a Conway-style transaction. The
transaction body term is carried through unchanged.
-}
module Cardano.Wallet.Tools.Sign.AttachWitness
    ( -- * Transaction body bytes
      TxBodyBytes (..)

      -- * Errors
    , AttachWitnessError (..)

      -- * CBOR attachment
    , transactionBodyBytes
    , attachWitnesses
    ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Word (Word64, Word8)

import Cardano.Wallet.Tools.Sign.Witness

-- | Raw CBOR transaction-body bytes offered to a signing backend.
newtype TxBodyBytes = TxBodyBytes
    { unTxBodyBytes :: ByteString
    }
    deriving stock (Eq, Show)

-- | Failures recognized while scanning or rewriting transaction CBOR.
data AttachWitnessError
    = AttachWitnessUnexpectedEnd
    | AttachWitnessTrailingBytes
    | AttachWitnessExpectedArray !Word64
    | AttachWitnessExpectedMap
    | AttachWitnessExpectedUnsigned
    | AttachWitnessExpectedTag258 !Word64
    | AttachWitnessIndefiniteUnsupported
    | AttachWitnessLengthOverflow !Word64
    | AttachWitnessReservedAdditional !Word8
    | AttachWitnessDuplicateVKeyWitnesses
    deriving stock (Eq, Show)

-- | Extract the top-level transaction body term bytes without decoding it.
transactionBodyBytes
    :: ByteString -> Either AttachWitnessError TxBodyBytes
transactionBodyBytes tx = do
    TxParts{txBody} <- splitTx tx
    Right (TxBodyBytes txBody)

{- | Attach detached vkey witnesses to the transaction witness set.

An empty witness list returns the original transaction bytes unchanged.
Only definite-length CBOR is supported; indefinite-length terms return
'AttachWitnessIndefiniteUnsupported'.
-}
attachWitnesses
    :: [DetachedWitness]
    -> ByteString
    -> Either AttachWitnessError ByteString
attachWitnesses [] tx =
    Right tx
attachWitnesses witnesses tx = do
    TxParts{txBody, txWitnessSet, txIsValid, txAuxiliaryData} <-
        splitTx tx
    witnessSet <- attachToWitnessSet witnesses txWitnessSet
    Right $
        BS.concat
            [ encodeHeader 4 4
            , txBody
            , witnessSet
            , txIsValid
            , txAuxiliaryData
            ]

data TxParts = TxParts
    { txBody :: !ByteString
    , txWitnessSet :: !ByteString
    , txIsValid :: !ByteString
    , txAuxiliaryData :: !ByteString
    }

splitTx :: ByteString -> Either AttachWitnessError TxParts
splitTx tx = do
    Header{headerMajor, headerValue, headerRest} <- decodeHeader tx
    if headerMajor == 4 && headerValue == 4
        then do
            (body, afterBody) <- splitTerm headerRest
            (witnessSet, afterWitnessSet) <- splitTerm afterBody
            (isValid, afterIsValid) <- splitTerm afterWitnessSet
            (auxiliaryData, rest) <- splitTerm afterIsValid
            if BS.null rest
                then
                    Right
                        TxParts
                            { txBody = body
                            , txWitnessSet = witnessSet
                            , txIsValid = isValid
                            , txAuxiliaryData = auxiliaryData
                            }
                else Left AttachWitnessTrailingBytes
        else Left (AttachWitnessExpectedArray headerValue)

attachToWitnessSet
    :: [DetachedWitness]
    -> ByteString
    -> Either AttachWitnessError ByteString
attachToWitnessSet witnesses witnessSetBytes = do
    entries <- parseWitnessSet witnessSetBytes
    (rewrittenEntries, foundVKey) <- rewriteEntries entries
    let newWitnesses = fmap encodeDetachedWitness witnesses
        withVKey
            | foundVKey = rewrittenEntries
            | otherwise =
                rewrittenEntries
                    <> [(BS.singleton 0x00, encodeVKeyWitnesses newWitnesses)]
    Right (encodeMap withVKey)
  where
    rewriteEntries [] =
        Right ([], False)
    rewriteEntries ((key, value) : rest)
        | isUnsignedKey 0 key = do
            existing <- parseVKeyWitnesses value
            (rewrittenRest, foundRest) <- rewriteEntries rest
            if foundRest
                then Left AttachWitnessDuplicateVKeyWitnesses
                else
                    Right
                        ( ( key
                          , encodeVKeyWitnesses
                                (existing <> fmap encodeDetachedWitness witnesses)
                          )
                            : rewrittenRest
                        , True
                        )
        | otherwise = do
            (rewrittenRest, foundRest) <- rewriteEntries rest
            Right ((key, value) : rewrittenRest, foundRest)

parseWitnessSet
    :: ByteString -> Either AttachWitnessError [(ByteString, ByteString)]
parseWitnessSet bytes = do
    Header{headerMajor, headerValue, headerRest} <- decodeHeader bytes
    if headerMajor == 5
        then do
            (entries, rest) <- splitMapEntries headerValue headerRest
            if BS.null rest
                then Right entries
                else Left AttachWitnessTrailingBytes
        else Left AttachWitnessExpectedMap

splitMapEntries
    :: Word64
    -> ByteString
    -> Either AttachWitnessError ([(ByteString, ByteString)], ByteString)
splitMapEntries 0 rest =
    Right ([], rest)
splitMapEntries count bytes = do
    (key, afterKey) <- splitTerm bytes
    (value, afterValue) <- splitTerm afterKey
    (entries, rest) <- splitMapEntries (count - 1) afterValue
    Right ((key, value) : entries, rest)

parseVKeyWitnesses
    :: ByteString -> Either AttachWitnessError [ByteString]
parseVKeyWitnesses bytes = do
    Header{headerMajor, headerValue, headerRest} <- decodeHeader bytes
    case headerMajor of
        4 ->
            parseArrayElements headerValue headerRest
        6
            | headerValue == 258 -> do
                (witnesses, rest) <- parseTaggedWitnessArray headerRest
                if BS.null rest
                    then Right witnesses
                    else Left AttachWitnessTrailingBytes
            | otherwise ->
                Left (AttachWitnessExpectedTag258 headerValue)
        _ ->
            Left (AttachWitnessExpectedArray 0)

parseTaggedWitnessArray
    :: ByteString -> Either AttachWitnessError ([ByteString], ByteString)
parseTaggedWitnessArray bytes = do
    Header{headerMajor, headerValue, headerRest} <- decodeHeader bytes
    if headerMajor == 4
        then parseArrayElementsWithRest headerValue headerRest
        else Left (AttachWitnessExpectedArray headerValue)

parseArrayElements
    :: Word64 -> ByteString -> Either AttachWitnessError [ByteString]
parseArrayElements count bytes = do
    (terms, rest) <- parseArrayElementsWithRest count bytes
    if BS.null rest
        then Right terms
        else Left AttachWitnessTrailingBytes

parseArrayElementsWithRest
    :: Word64
    -> ByteString
    -> Either AttachWitnessError ([ByteString], ByteString)
parseArrayElementsWithRest 0 rest =
    Right ([], rest)
parseArrayElementsWithRest count bytes = do
    (term, afterTerm) <- splitTerm bytes
    (terms, rest) <- parseArrayElementsWithRest (count - 1) afterTerm
    Right (term : terms, rest)

encodeVKeyWitnesses :: [ByteString] -> ByteString
encodeVKeyWitnesses witnesses =
    BS.concat
        [ BS.pack [0xd9, 0x01, 0x02]
        , encodeHeader 4 (fromIntegral (length witnesses))
        , BS.concat witnesses
        ]

encodeMap :: [(ByteString, ByteString)] -> ByteString
encodeMap entries =
    BS.concat
        [ encodeHeader 5 (fromIntegral (length entries))
        , BS.concat [key <> value | (key, value) <- entries]
        ]

isUnsignedKey :: Word64 -> ByteString -> Bool
isUnsignedKey expected bytes =
    case decodeHeader bytes of
        Right Header{headerMajor, headerValue, headerRest} ->
            headerMajor == 0 && headerValue == expected && BS.null headerRest
        Left _ ->
            False

splitTerm
    :: ByteString -> Either AttachWitnessError (ByteString, ByteString)
splitTerm bytes = do
    len <- termLength bytes
    let (term, rest) = BS.splitAt len bytes
    Right (term, rest)

termLength :: ByteString -> Either AttachWitnessError Int
termLength bytes = do
    Header{headerMajor, headerValue, headerLength, headerRest} <-
        decodeHeader bytes
    case headerMajor of
        0 ->
            Right headerLength
        1 ->
            Right headerLength
        2 ->
            definiteLength headerLength headerValue headerRest
        3 ->
            definiteLength headerLength headerValue headerRest
        4 ->
            nestedLength headerLength headerValue headerRest
        5 ->
            nestedLength headerLength (headerValue * 2) headerRest
        6 -> do
            nested <- termLength headerRest
            Right (headerLength + nested)
        7 ->
            Right headerLength
        _ ->
            Left AttachWitnessUnexpectedEnd

definiteLength
    :: Int
    -> Word64
    -> ByteString
    -> Either AttachWitnessError Int
definiteLength headerLength payloadLength rest = do
    payloadLen <- word64ToInt payloadLength
    if BS.length rest >= payloadLen
        then Right (headerLength + payloadLen)
        else Left AttachWitnessUnexpectedEnd

nestedLength
    :: Int
    -> Word64
    -> ByteString
    -> Either AttachWitnessError Int
nestedLength headerLength count rest = do
    (_, payloadLen) <- consumeTerms count rest
    Right (headerLength + payloadLen)

consumeTerms
    :: Word64
    -> ByteString
    -> Either AttachWitnessError (ByteString, Int)
consumeTerms 0 rest =
    Right (rest, 0)
consumeTerms count bytes = do
    len <- termLength bytes
    if BS.length bytes >= len
        then do
            let after = BS.drop len bytes
            (rest, tailLen) <- consumeTerms (count - 1) after
            Right (rest, len + tailLen)
        else Left AttachWitnessUnexpectedEnd

data Header = Header
    { headerMajor :: !Word8
    , headerValue :: !Word64
    , headerLength :: !Int
    , headerRest :: !ByteString
    }

decodeHeader :: ByteString -> Either AttachWitnessError Header
decodeHeader bytes = case BS.uncons bytes of
    Nothing ->
        Left AttachWitnessUnexpectedEnd
    Just (initial, rest) -> do
        (value, extraLength, afterAdditional) <-
            decodeAdditional (initial .&. 0x1f) rest
        Right
            Header
                { headerMajor = initial `div` 32
                , headerValue = value
                , headerLength = 1 + extraLength
                , headerRest = afterAdditional
                }

decodeAdditional
    :: Word8
    -> ByteString
    -> Either AttachWitnessError (Word64, Int, ByteString)
decodeAdditional additional rest
    | additional < 24 =
        Right (fromIntegral additional, 0, rest)
    | additional == 24 = do
        (value, after) <- readWord8 rest
        Right (value, 1, after)
    | additional == 25 = do
        (value, after) <- readBigEndian 2 rest
        Right (value, 2, after)
    | additional == 26 = do
        (value, after) <- readBigEndian 4 rest
        Right (value, 4, after)
    | additional == 27 = do
        (value, after) <- readBigEndian 8 rest
        Right (value, 8, after)
    | additional == 31 =
        Left AttachWitnessIndefiniteUnsupported
    | otherwise =
        Left (AttachWitnessReservedAdditional additional)

readWord8
    :: ByteString -> Either AttachWitnessError (Word64, ByteString)
readWord8 bytes = case BS.uncons bytes of
    Nothing ->
        Left AttachWitnessUnexpectedEnd
    Just (byte, rest) ->
        Right (fromIntegral byte, rest)

readBigEndian
    :: Int -> ByteString -> Either AttachWitnessError (Word64, ByteString)
readBigEndian count bytes =
    let (raw, rest) = BS.splitAt count bytes
    in  if BS.length raw == count
            then Right (BS.foldl' step 0 raw, rest)
            else Left AttachWitnessUnexpectedEnd
  where
    step acc byte = acc * 256 + fromIntegral byte

word64ToInt :: Word64 -> Either AttachWitnessError Int
word64ToInt value
    | value <= fromIntegral (maxBound :: Int) =
        Right (fromIntegral value)
    | otherwise =
        Left (AttachWitnessLengthOverflow value)

encodeHeader :: Word8 -> Word64 -> ByteString
encodeHeader major value
    | value < 24 =
        BS.singleton (majorPrefix + fromIntegral value)
    | value <= 0xff =
        BS.pack [majorPrefix + 24, fromIntegral value]
    | value <= 0xffff =
        BS.cons (majorPrefix + 25) (encodeBigEndian 2 value)
    | value <= 0xffffffff =
        BS.cons (majorPrefix + 26) (encodeBigEndian 4 value)
    | otherwise =
        BS.cons (majorPrefix + 27) (encodeBigEndian 8 value)
  where
    majorPrefix = major * 32

encodeBigEndian :: Int -> Word64 -> ByteString
encodeBigEndian count value =
    BS.pack
        [ fromIntegral (value `div` (256 ^ power)) :: Word8
        | power <- reverse [0 .. count - 1]
        ]
