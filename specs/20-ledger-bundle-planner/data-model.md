# Data model (#20)

| type | fields / constructors | invariants |
|---|---|---|
| `TextEnvelope` | `envelopeType`, `envelopeDescription`, `envelopeCborHex` :: `Text` | JSON keys `type`, `description`, `cborHex` |
| `BundleTransaction` | `bundleTxIdentity :: ByteString` (32 bytes), `bundleTxEnvelope :: TextEnvelope`, `bundleTxDeadline :: Maybe Word64`, `bundleTxEffects :: [Text]` | identity is 64 hex digits in JSON; an effect has no line break; effects are carried, never trusted |
| `Bundle` | `bundleCommand :: Text`, `bundleNetworkMagic :: Word32`, `bundleStateToken :: Maybe Text`, `bundleSigners :: NonEmpty Text`, `bundleTransactions :: NonEmpty BundleTransaction` | version 1 only; signers are bech32 addresses; transactions in submission order; state token opaque, caller-set |
| `BundleRefusal` | unknown version; field + reason; envelope wrong type; envelope undecodable; identity mismatch (recorded, actual); deadline mismatch (recorded, actual, identity); duplicate identity; signer not covered (key hash, identity) | rendered as one line naming the failed check; never names a key or passphrase; no rendering mentions singular |
| `ChainPoint` | `Genesis` \| `At SlotNo ByteString` | — |
| `InclusionStatus` | `IncludedAt ChainPoint Word64` (confirmations) \| `NotOnChain` | — |
| `PlanStep` | `PlanSend BundleTransaction (Tx ConwayEra) [DetachedWitness]` \| `PlanFound BundleTransaction ChainPoint Word64` | steps in bundle order; a send step carries exactly its verified witnesses |
| `SubmitRefusal` | bundle refused; witness foreign body (key); witness unneeded key (key hash); witness missing (key hash, identity); body expired (identity, bound, tip); input unresolved (`TxIn`) | one line each, no secret |
| `BundleCheckOptions` | the bundle file path | — |

`DetachedWitness` is the core type (`detachedWitnessVKey`,
`detachedWitnessSignature`).
