# Bundle test fixtures

Recorded data, not a check. The specs read these files at run time and
derive every expected value from them or from a producer; none of it is
typed beside an assertion.

## `cardano-cli-tx-body.json`, `cardano-cli-tx-witness.json`

Byte-for-byte copies of lambdasistemi/singular
`offchain/test/fixtures/bundle/` at `origin/main`
`a1cb80cc757588f2efd6097f280e7a28ea86b432`, read with
`git show origin/main:<path>`.

They are the exact JSON text envelopes the official `cardano-cli` wrote:

```text
cardano-cli 10.15.1.0 - linux-x86_64 - ghc-9.6
git rev 1e6d8228693ab2aa4e1d7305e7bdcc57cdd278e4
```

generated offline with `cardano-cli conway transaction build-raw` and
`cardano-cli conway transaction witness` from a dummy all-zero input and
a throwaway payment key (not committed). The envelope shape, not ledger
validity, is what they pin:

- `cardano-cli-tx-body.json` is typed `Tx ConwayEra`, described
  `Ledger Cddl Format`, and carries the complete unsigned transaction:
  an array of body, empty witness set, validity flag and auxiliary data.
- `cardano-cli-tx-witness.json` is typed `TxWitness ConwayEra`,
  described `Key Witness ShelleyEra`, and carries one verification-key
  witness: an array of the 32-byte key and the 64-byte signature.

## `unsigned-bundle.json`

A byte-for-byte copy of the same singular path and revision: a bundle v1
written by singular's bundle writer, two transactions in submission
order, one signer address. Reading it unchanged is the compatibility
claim; the spec also proves it equals what this library's encoder writes
for the same bundle, so the file is the encoder's output and not a typed
expectation.

## `golden/`

Byte-for-byte copies of `test/fixtures/tx-sign/<name>` at
lambdasistemi/cardano-tx-tools `origin/main`
`1b623b133989d1b1c0d4e52164d26ef76f0d0510`, read with
`git show origin/main:test/fixtures/tx-sign/<name>`. Their own provenance
is that repository's `test/fixtures/tx-sign/fixture-source.md`:

- `payment.skey` is a generated throwaway `cardano-cli` payment signing
  key.
- `unsigned.cbor.hex` is the transaction `cardano-cli conway transaction
  build-raw` made for it, requiring that key's hash as a signer.
- `witness.expected.hex` is the witness `cardano-cli conway transaction
  witness` made for `payment.skey` over `unsigned.cbor.hex`: the raw
  array of the 32-byte verification key and the 64-byte signature, as
  hex.

The signer spec requires the library's detached witness, signed with
`payment.skey` over the body hash of `unsigned.cbor.hex`, to equal
`witness.expected.hex` byte for byte.

## `example-bundle.json`

The bundle the documentation page shows. Made by this library's own
encoder from the spec's sample bundle (`encodeBundle sampleBundle`, the
one-line JSON it writes) and pretty-printed with `jq .`, which keeps the
key order; `jq -c .` of the file is the encoder's output byte for byte.
The spec proves the file decodes to the sample bundle, and
`docs/bundle.md` includes it, so what a reader copies is what the codec
reads.
