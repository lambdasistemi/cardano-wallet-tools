# Functions model (#20)

`Tx` below is `Cardano.Ledger.Core.Tx ConwayEra` (no alias from
cardano-tx-tools).

## Ledger.Envelope

- `transactionEnvelope :: (tx :: Tx) -> TextEnvelope`
- `decodeTransactionEnvelope :: (envelope :: TextEnvelope) -> Either String Tx`
- `witnessEnvelope :: (witness :: DetachedWitness) -> TextEnvelope`
- `decodeWitnessEnvelope :: (bytes :: ByteString) -> Either BundleRefusal DetachedWitness` (or an envelope-local refusal type, owner's choice; documented in the Contract)
- `encodeTextEnvelope :: (envelope :: TextEnvelope) -> ByteString`
- `transactionEnvelopeType :: Text`, `acceptedTransactionEnvelopeTypes :: [Text]`

## Ledger.Bundle

- `bundleVersion :: Word`
- `encodeBundle :: (bundle :: Bundle) -> ByteString` — deterministic
- `decodeBundle :: (bytes :: ByteString) -> Either BundleRefusal Bundle`
- `bundleRefusals :: (bundle :: Bundle) -> [BundleRefusal]` — every failed offline check
- `checkBundle :: (bundle :: Bundle) -> Either BundleRefusal ()` — the first of `bundleRefusals`
- `bodyIdentity :: (tx :: Tx) -> ByteString`
- `bodyDeadline :: (tx :: Tx) -> Maybe Word64`
- `renderBundleRefusal :: (refusal :: BundleRefusal) -> String`

## Ledger.Witness

- `detachedWitness :: (key :: SignKeyDSIGN Ed25519DSIGN) -> (tx :: Tx) -> DetachedWitness`
- `assembleWitnessed :: (tx :: Tx) -> (witnesses :: [DetachedWitness]) -> Tx` — key witnesses replaced, body bytes and identity preserved

## Ledger.Submit

- `neededKeys :: (bundle :: Bundle) -> (resolved :: Map TxIn (TxOut ConwayEra)) -> Either SubmitRefusal (Map ByteString (Set ByteString))`
- `matchWitnesses :: (bundle :: Bundle) -> (witnesses :: [DetachedWitness]) -> Either SubmitRefusal (Map ByteString [DetachedWitness])`
- `planSubmission :: (bundle :: Bundle) -> (witnesses :: [DetachedWitness]) -> (resolved :: Map TxIn (TxOut ConwayEra)) -> (statuses :: Map ByteString InclusionStatus) -> (tip :: Word64) -> Either SubmitRefusal (NonEmpty PlanStep)` — pure
- `renderSubmitRefusal :: (refusal :: SubmitRefusal) -> String`

## Ledger.Cli.Bundle

- `bundleCheckParser :: Parser BundleCheckOptions`
- `runBundleCheck :: (options :: BundleCheckOptions) -> IO (Either [String] String)` — `Right` summary, `Left` one line per failed check; `cwt` maps `Left` to a non-zero exit
