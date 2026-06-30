{- |
Module      : Cardano.Wallet.Tools.Sign.Witness
Description : Detached vkey witness CBOR.
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

Encoders and decoders for one detached vkey witness. The key and
signature bytes are opaque; this module only recognizes the CBOR wire
shapes used by the ledger raw witness and the cardano-cli Shelley
key-witness envelope.
-}
module Cardano.Wallet.Tools.Sign.Witness
    ( -- * Detached witnesses
      DetachedWitness (..)

      -- * Decode errors
    , WitnessDecodeError (..)

      -- * CBOR
    , decodeDetachedWitness
    , encodeDetachedWitness
    , encodeShelleyWitnessEnvelope
    ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Word (Word64, Word8)

-- | One detached vkey witness, with opaque key and signature bytes.
data DetachedWitness = DetachedWitness
    { detachedWitnessVKey :: !ByteString
    , detachedWitnessSignature :: !ByteString
    }
    deriving stock (Eq, Show)

-- | Failures recognized while decoding detached witness CBOR.
data WitnessDecodeError
    = WitnessDecodeUnexpectedEnd
    | WitnessDecodeTrailingBytes
    | WitnessDecodeExpectedArray !Word64
    | WitnessDecodeExpectedByteString
    | WitnessDecodeExpectedUnsigned
    | WitnessDecodeIndefiniteUnsupported
    | WitnessDecodeLengthOverflow !Word64
    | WitnessEnvelopeTagUnsupported !Word64
    deriving stock (Eq, Show)

{- | Decode either raw @[vkey, signature]@ CBOR or a Shelley envelope
@[0, [vkey, signature]]@.
-}
decodeDetachedWitness
    :: ByteString -> Either WitnessDecodeError DetachedWitness
decodeDetachedWitness bytes = do
    (witness, rest) <- decodeWitness bytes
    if BS.null rest
        then Right witness
        else Left WitnessDecodeTrailingBytes

-- | Encode a raw detached vkey witness as @[vkey, signature]@.
encodeDetachedWitness :: DetachedWitness -> ByteString
encodeDetachedWitness witness =
    BS.concat
        [ BS.singleton 0x82
        , encodeBytes (detachedWitnessVKey witness)
        , encodeBytes (detachedWitnessSignature witness)
        ]

{- | Encode a cardano-cli Shelley key-witness envelope as
@[0, [vkey, signature]]@.
-}
encodeShelleyWitnessEnvelope :: DetachedWitness -> ByteString
encodeShelleyWitnessEnvelope witness =
    BS.concat
        [ BS.pack [0x82, 0x00]
        , encodeDetachedWitness witness
        ]

decodeWitness
    :: ByteString -> Either WitnessDecodeError (DetachedWitness, ByteString)
decodeWitness bytes = do
    rest <- decodeArrayLen 2 bytes
    case BS.uncons rest of
        Nothing ->
            Left WitnessDecodeUnexpectedEnd
        Just (initial, _)
            | majorType initial == 0 -> do
                (tag, afterTag) <- decodeUnsigned rest
                if tag == 0
                    then decodeRawWitness afterTag
                    else Left (WitnessEnvelopeTagUnsupported tag)
            | majorType initial == 2 ->
                decodeRawWitness bytes
            | otherwise ->
                Left WitnessDecodeExpectedByteString

decodeRawWitness
    :: ByteString -> Either WitnessDecodeError (DetachedWitness, ByteString)
decodeRawWitness bytes = do
    rest <- decodeArrayLen 2 bytes
    (vkey, afterVKey) <- decodeBytes rest
    (signature, afterSignature) <- decodeBytes afterVKey
    Right
        ( DetachedWitness
            { detachedWitnessVKey = vkey
            , detachedWitnessSignature = signature
            }
        , afterSignature
        )

decodeArrayLen
    :: Word64 -> ByteString -> Either WitnessDecodeError ByteString
decodeArrayLen expected bytes = do
    (actual, rest) <- decodeHeader 4 bytes
    if actual == expected
        then Right rest
        else Left (WitnessDecodeExpectedArray actual)

decodeBytes
    :: ByteString -> Either WitnessDecodeError (ByteString, ByteString)
decodeBytes bytes = do
    (len, rest) <- decodeHeader 2 bytes
    n <- word64ToInt len
    let (chunk, afterChunk) = BS.splitAt n rest
    if BS.length chunk == n
        then Right (chunk, afterChunk)
        else Left WitnessDecodeUnexpectedEnd

decodeUnsigned
    :: ByteString -> Either WitnessDecodeError (Word64, ByteString)
decodeUnsigned = decodeHeader 0

decodeHeader
    :: Word8
    -> ByteString
    -> Either WitnessDecodeError (Word64, ByteString)
decodeHeader expectedMajor bytes = case BS.uncons bytes of
    Nothing ->
        Left WitnessDecodeUnexpectedEnd
    Just (initial, rest)
        | majorType initial /= expectedMajor ->
            Left (expectedError expectedMajor)
        | otherwise ->
            decodeAdditional (initial .&. 0x1f) rest

decodeAdditional
    :: Word8 -> ByteString -> Either WitnessDecodeError (Word64, ByteString)
decodeAdditional additional rest
    | additional < 24 =
        Right (fromIntegral additional, rest)
    | additional == 24 =
        readWord8 rest
    | additional == 25 =
        readBigEndian 2 rest
    | additional == 26 =
        readBigEndian 4 rest
    | additional == 27 =
        readBigEndian 8 rest
    | additional == 31 =
        Left WitnessDecodeIndefiniteUnsupported
    | otherwise =
        Left WitnessDecodeUnexpectedEnd

readWord8
    :: ByteString -> Either WitnessDecodeError (Word64, ByteString)
readWord8 bytes = case BS.uncons bytes of
    Nothing ->
        Left WitnessDecodeUnexpectedEnd
    Just (byte, rest) ->
        Right (fromIntegral byte, rest)

readBigEndian
    :: Int -> ByteString -> Either WitnessDecodeError (Word64, ByteString)
readBigEndian count bytes =
    let (raw, rest) = BS.splitAt count bytes
    in  if BS.length raw == count
            then Right (BS.foldl' step 0 raw, rest)
            else Left WitnessDecodeUnexpectedEnd
  where
    step acc byte = acc * 256 + fromIntegral byte

word64ToInt :: Word64 -> Either WitnessDecodeError Int
word64ToInt value
    | value <= fromIntegral (maxBound :: Int) =
        Right (fromIntegral value)
    | otherwise =
        Left (WitnessDecodeLengthOverflow value)

majorType :: Word8 -> Word8
majorType byte = byte `div` 32

expectedError :: Word8 -> WitnessDecodeError
expectedError 0 = WitnessDecodeExpectedUnsigned
expectedError 2 = WitnessDecodeExpectedByteString
expectedError 4 = WitnessDecodeExpectedArray 0
expectedError _ = WitnessDecodeUnexpectedEnd

encodeBytes :: ByteString -> ByteString
encodeBytes bytes =
    BS.concat
        [ encodeHeader 2 (fromIntegral (BS.length bytes))
        , bytes
        ]

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
