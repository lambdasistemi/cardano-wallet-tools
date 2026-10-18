{- |
Module      : Cardano.Wallet.Tools.Vault.Plugin.Payload
Description : The payload of an age file, sealed and opened under a file key
Copyright   : (c) Paolo Veronelli, 2026
License     : Apache-2.0

The part of an age v1 file that follows the header: the 16-byte payload
key nonce and the plaintext in 64 KiB ChaCha20-Poly1305 chunks, the
last of them final. The age library keeps its file-key handling inside
recipients and identities, so a file key a plugin wrapped has to be
carried through the payload chunk functions it does export.

A payload ends with exactly one final chunk. The final chunk is the last
one and may be shorter than a full chunk; it is empty only when the
whole payload is.
-}
module Cardano.Wallet.Tools.Vault.Plugin.Payload
    ( sealPayload
    , openPayload
    ) where

import Crypto.Age.Conduit
    ( decryptPayloadChunk
    , encryptPayloadChunk
    )
import Crypto.Age.Key
    ( FileKey
    , PayloadKeyNonce
    , bytesToPayloadKeyNonce
    , mkPayloadKey
    , payloadKeyNonceToBytes
    )
import Crypto.Age.Payload.Ciphertext
    ( CiphertextPayloadChunk (..)
    , ciphertextChunkSize
    , ciphertextPayloadChunkToBytes
    , mkFinalCiphertextPayloadChunk
    , mkNormalCiphertextPayloadChunk
    )
import Crypto.Age.Payload.Counter
    ( PayloadChunkCounter
    , incrementPayloadChunkCounter
    , zeroPayloadChunkCounter
    )
import Crypto.Age.Payload.Plaintext
    ( PlaintextPayloadChunk (..)
    , mkFinalPlaintextPayloadChunk
    , mkNormalPlaintextPayloadChunk
    , plaintextChunkSize
    , plaintextPayloadChunkToBytes
    )
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS

{- | The payload of an age file: the nonce, then the plaintext sealed
under the key derived from the file key and the nonce. Nothing only for
a plaintext of more chunks than a counter can number.
-}
sealPayload
    :: FileKey -> PayloadKeyNonce -> ByteString -> Maybe ByteString
sealPayload fileKey nonce plaintext = do
    chunks <- traverse plaintextChunk (pieces plaintext)
    numbered <- counters (length chunks)
    pure $
        payloadKeyNonceToBytes nonce
            <> BS.concat
                [ ciphertextPayloadChunkToBytes
                    (encryptPayloadChunk key counter chunk)
                | (counter, chunk) <- zip numbered chunks
                ]
  where
    key = mkPayloadKey nonce fileKey

{- | The plaintext of an age file payload under a file key, or nothing
when it is not a payload of that key: a nonce that is not 16 bytes, no
final chunk, a chunk that does not authenticate, an empty final chunk
after others.
-}
openPayload :: FileKey -> ByteString -> Maybe ByteString
openPayload fileKey payload = do
    let (nonceBytes, rest) = BS.splitAt 16 payload
    nonce <- bytesToPayloadKeyNonce nonceBytes
    ciphertexts <- ciphertextChunks rest
    numbered <- counters (length ciphertexts)
    plaintexts <-
        traverse
            (either (const Nothing) Just)
            [ decryptPayloadChunk (mkPayloadKey nonce fileKey) counter chunk
            | (counter, chunk) <- zip numbered ciphertexts
            ]
    let bytes = plaintextPayloadChunkToBytes <$> plaintexts
    case reverse bytes of
        final : _ : _ | BS.null final -> Nothing
        _ -> Just (BS.concat bytes)

-- | The plaintext cut into chunks: full chunks, then the final one.
pieces :: ByteString -> [(Bool, ByteString)]
pieces bytes
    | BS.length bytes <= plaintextChunkSize = [(True, bytes)]
    | otherwise =
        let (chunk, rest) = BS.splitAt plaintextChunkSize bytes
        in  (False, chunk) : pieces rest

plaintextChunk :: (Bool, ByteString) -> Maybe PlaintextPayloadChunk
plaintextChunk (isFinal, bytes)
    | isFinal =
        PlaintextPayloadChunkFinal <$> mkFinalPlaintextPayloadChunk bytes
    | otherwise =
        PlaintextPayloadChunkNormal <$> mkNormalPlaintextPayloadChunk bytes

-- | The ciphertext cut into full chunks and one final chunk.
ciphertextChunks :: ByteString -> Maybe [CiphertextPayloadChunk]
ciphertextChunks bytes
    | BS.null bytes = Nothing
    | BS.length bytes > ciphertextChunkSize = do
        normal <-
            mkNormalCiphertextPayloadChunk (BS.take ciphertextChunkSize bytes)
        rest <- ciphertextChunks (BS.drop ciphertextChunkSize bytes)
        pure (CiphertextPayloadChunkNormal normal : rest)
    | otherwise =
        (\final -> [CiphertextPayloadChunkFinal final])
            <$> mkFinalCiphertextPayloadChunk bytes

-- | The chunk counters 0 to n - 1.
counters :: Int -> Maybe [PayloadChunkCounter]
counters n =
    sequence
        ( take
            n
            ( iterate
                (>>= incrementPayloadChunkCounter)
                (Just zeroPayloadChunkCounter)
            )
        )
