# Bundle v1

A bundle is the file a transaction-building tool hands an offline
signer: the unsigned transactions of one operation in submission order,
the addresses that must sign, and what the writer claims each
transaction does. This page specifies the format, the checks that can be
made on it with no network, the witnesses that come back, and how all of
it maps one-to-one onto the CIP-0103 calls `signTxs` and `submitTxs`.

No standard file format exists for this. CIP-0103 defines a wallet API
and no file, and CIP-1854 leaves transport out of scope; a bundle is the
file form of the ordered argument that API takes.

The format, the checks and the planner are implemented by the public
sublibrary `cardano-wallet-tools:ledger`. The command `cwt bundle check`
runs the checks on a file.

## The file

One JSON object. Unknown keys are ignored; the keys below are read.

| key | value |
|---|---|
| `version` | the number `1`. Any other value is refused by name. |
| `command` | text: the name of the command that wrote the bundle. |
| `networkMagic` | number: the network the transactions are built for. |
| `stateToken` | text or `null`, and may be absent. Opaque: set by the caller, carried verbatim, never interpreted. |
| `signers` | a non-empty list of bech32 addresses that must sign. |
| `transactions` | a non-empty list, in submission order. |

Each entry of `transactions`:

| key | value |
|---|---|
| `identity` | 64 hex digits: the hash of the transaction body, as the ledger computes a transaction id. |
| `envelope` | the transaction's text envelope: `type`, `description` and `cborHex`. |
| `deadline` | a slot number or `null`: the body's validity upper bound. |
| `effects` | a list of texts, each one line: what the writer claims the transaction does. Carried and shown, never trusted. |

A bundle written by the library, two transactions and one signer:

```json
--8<-- "test/fixtures/bundle/example-bundle.json"
```

The second transaction may spend an output of the first: an input that
no earlier transaction of the bundle produces has to be on the chain.

## Envelopes

An unsigned transaction is the text envelope `cardano-cli` writes: the
complete Conway transaction (body, empty witness set, validity flag and
auxiliary data), not a bare body.

| | `type` | `description` |
|---|---|---|
| written | `Unwitnessed Tx ConwayEra` | `Ledger Cddl Format` |
| also read | `Tx ConwayEra`, the label `cardano-cli conway transaction build-raw` writes | `Ledger Cddl Format` |

A detached witness is the envelope `cardano-cli conway transaction
witness` writes: `type` `TxWitness ConwayEra`, `description` `Key
Witness ShelleyEra`, and a `cborHex` that is the CBOR array of the
32-byte verification key and the 64-byte signature. Both forms are
checked against the official tool's own files, read and written.

## Offline checks

Everything a bundle says about itself can be checked with no network and
no key:

| check | what is proved |
|---|---|
| `envelope` | each envelope's `cborHex` decodes to a complete Conway transaction. |
| `identity` | each recorded `identity` is the hash of its decoded transaction's body. |
| `deadline` | each recorded `deadline` is the body's validity upper bound. |
| `distinct-identities` | no identity is recorded for two transactions. |
| `signers` | every required signer of every body is the payment key hash of an address in `signers`. |

Whether the `signers` list is complete cannot be checked offline: a
required signer is covered when some listed address carries its key
hash, and a key that a transaction needs only because it owns an input
is found by the submitting side, which sees the chain.

`cwt bundle check FILE` runs them:

| outcome | exit status | output |
|---|---|---|
| every check passes | 0 | one summary line on standard output: `ok: transactions=N signers=M networkMagic=K` |
| checks fail | non-zero | one line per failed check on standard error, nothing on standard output |
| the file cannot be read | non-zero | one line on standard error naming the file and why |
| the file is not a bundle | non-zero | one line on standard error naming the first thing wrong with it |

Each failure line starts with the name of its check and a colon: the
five names above, and `version`, `field` and `envelope-type` for a file
that is not a readable version 1 bundle. A bundle that fails several
checks at once gets several lines, in the order of the table above; for
example

```text
identity: the transaction's recorded identity … is not the hash of its body, …
deadline: the transaction … records deadline 4000 and its body's validity upper bound is 1000
signers: the key hash … is required by the transaction … and no signer address covers it
```

## Witnesses

A witness is detached from the transaction it signs: the signer's
verification key and its Ed25519 signature over the transaction's
identity, the blake2b-256 hash of the body bytes. Signing changes only
the witness set, so the body and the identity are the same before and
after.

A witness belongs to the body whose identity its signature verifies
over. The name of the file that holds it plays no part, and a witness
that verifies against no body of the bundle is refused.

## Submitting

The planner of the sublibrary turns a bundle, the detached witnesses,
the outputs the inputs resolve to, where the chain holds each
transaction and the tip slot into an ordered plan, or into a refusal.

- **Checks first.** The planner runs the offline checks on the transactions
  still to send before anything else and refuses a bundle that fails
  one, with the first failed check.
- **Needed keys.** For each transaction: its required signers and the
  payment key hashes of the outputs its inputs and collateral inputs
  spend. A script credential adds nothing. An input that no earlier
  transaction of the bundle produces and the caller did not resolve is
  refused.
- **Pairing.** Each witness is paired with its body by signature: it
  belongs to the transaction whose body hash its signature verifies over,
  which the checks have proved is the identity the bundle records (the
  pairing function used alone computes that hash from the decoded body).
  A witness for a key no transaction needs, a second witness for a key
  already covered, and a transaction missing a witness for a key it
  needs are refused.
- **The plan.** One step per transaction, in the bundle's order: send it
  with exactly its verified witnesses, or skip it because the chain
  already holds it. A transaction is held when the chain view gives it an
  inclusion point; any other one, whether the view says it is not on the
  chain or says nothing, is still to send and is judged the same way. A
  transaction the chain holds is not judged: it is not decoded, it needs
  no witness, its spent inputs are no longer there to resolve and its
  deadline does not matter.
- **Before the first send.** Every refusal, including a body whose
  validity upper bound is at or before the tip, is raised before the plan
  exists. There is no plan whose first steps could already have been
  sent.

## CIP-0103

CIP-0103 adds two bulk calls to the wallet API: `signTxs`, which takes
an array of transactions to sign and returns an array of witness sets,
and `submitTxs`, which takes an array of signed transactions and returns
their ids. A bundle maps onto them one to one:

| bundle v1 | CIP-0103 |
|---|---|
| `transactions[i].envelope`, the complete unsigned transaction | `txs[i].cbor`, an element of the `signTxs` argument |
| the order of `transactions` | the order of `txs`: the wallet processes the array in the order given |
| the witnesses the signer returns for transaction `i`, taken together | element `i` of the `signTxs` result: one `transaction_witness_set` per index, in the order of the input |
| a signer that cannot sign any one transaction returns no witnesses for the bundle | `signTxs` is all-or-nothing: on a sign error for any transaction, no witnesses are returned, and the error should refer to the transaction that failed |
| the signed transactions, in the bundle's order | the argument of `submitTxs`, submitted in the order given |
| `transactions[i].identity` | element `i` of the `submitTxs` result: the id of the transaction at that index |

Two differences are deliberate.

- **Failure while sending.** `submitTxs` attempts every transaction even
  after an error and reports a result per index. The plan refuses
  everything it can refuse before sending the first transaction, and
  skips the transactions the chain already holds, so that a bundle that
  was partly submitted can be submitted again without sending anything
  twice.
- **Who holds which key.** A `signTxs` request is answered by one wallet.
  A bundle lists every address that must sign, and the witnesses may come
  from several holders, each signing the whole ordered list; the planner
  checks that together they cover every key the transactions need.

## Library

| module | content |
|---|---|
| `Cardano.Wallet.Tools.Ledger.Envelope` | the text envelopes of transactions and witnesses |
| `Cardano.Wallet.Tools.Ledger.Bundle` | the types, the codec, the offline checks and their refusals |
| `Cardano.Wallet.Tools.Ledger.Witness` | the ledger-typed detached witness and the assembly of a witnessed transaction |
| `Cardano.Wallet.Tools.Ledger.Submit` | the needed keys, the pairing, the plan and its refusals |
| `Cardano.Wallet.Tools.Ledger.Cli.Bundle` | the parser and runner of `cwt bundle check` |
