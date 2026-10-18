# Vault test fixtures

Recorded data, not a check. Every file below was produced by the tool
named beside it; none was typed or edited by hand. The specs read these
files at run time and derive every expected value from them.

Tools (store paths pinned at generation time, 2026-10-18):

| tool | version | path |
|---|---|---|
| `cardano-cli` | 10.15.1.0 (git rev 1e6d8228) | `/nix/store/bz64647x6q7ghmdqlax7nb08a9l0gfn6-cardano-cli-exe-cardano-cli-10.15.1.0/bin/cardano-cli` |
| `age` (stock, with `age-plugin-batchpass`) | v1.3.1 | `/nix/store/bx602yqsxz88pr178n8yk1pp7d1vll5k-age-1.3.1/bin/age` |
| `jq` | system | assembles the payload JSON |

## `payment.skey`, `payment.vkey`

A cardano-cli payment key pair, used by the stock-`age` interop examples.

```sh
cardano-cli address key-gen --normal-key \
  --verification-key-file payment.vkey \
  --signing-key-file payment.skey
```

## `tx-sign/`

A vault in the cardano-tx-tools `tx-sign vault` payload format
(`src/Cardano/Tx/Sign/Vault.hs` at `1b623b1`), holding three identities
so the identity selector is exercised with more than one candidate.

`alice`, `bob` and `carol` are three independent cardano-cli key pairs:

```sh
for n in alice bob carol; do
  cardano-cli address key-gen --normal-key \
    --verification-key-file tx-sign/$n.vkey \
    --signing-key-file tx-sign/$n.skey
done
```

`payload.json` is the plaintext payload. Each identity's `keyHash` is
`cardano-cli address key-hash` of its verification key, and its
`keyEnvelope` is the unmodified `.skey` file:

```sh
for n in alice bob carol; do
  cardano-cli address key-hash \
    --payment-verification-key-file tx-sign/$n.vkey \
    --out-file $n.keyhash
done
jq -n --slurpfile a alice.skey --slurpfile b bob.skey --slurpfile c carol.skey \
  --rawfile ah alice.keyhash --rawfile bh bob.keyhash --rawfile ch carol.keyhash '
  def identity($label; $hash; $env):
    { label: $label, network: "preprod", keyHash: ($hash | rtrimstr("\n")),
      source: { kind: "cardano-cli-skey", keyEnvelope: $env } };
  { cardanoTxSignVault: { version: 1, identities: {
      alice: identity("alice"; $ah; $a[0]),
      bob:   identity("bob";   $bh; $b[0]),
      carol: identity("carol"; $ch; $c[0]) } } }' > tx-sign/payload.json
```

`passphrase` is the vault passphrase, one line. `vault.age` is the
payload encrypted by stock `age` (not by any code in this repository),
passphrase from the environment, scrypt work factor 18 (stock `age`'s
fixed default, equal to the cap):

```sh
printf 'tx-sign fixture passphrase\n' > tx-sign/passphrase
AGE_PASSPHRASE="$(head -1 tx-sign/passphrase)" \
  age -e -j batchpass -o tx-sign/vault.age tx-sign/payload.json
```

Check at generation: `age -d -j batchpass tx-sign/vault.age` with that
passphrase reproduces `payload.json` byte for byte.

## `golden/`

Fixtures for the witness, the `addr_xsk` source and the stored key hash.
Recorded data, not a check; the specs read these files at run time.

Tools (store paths pinned at generation time, 2026-10-18):

| tool | version | path |
|---|---|---|
| `tx-sign` (cardano-tx-tools exe, built 2026-06-26 from the 0.2.3.0 line; the payload it writes matches `src/Cardano/Tx/Sign/Vault.hs` at `1b623b1`) | 0.2.3.0 | `/code/cardano-tx-tools/dist-newstyle/build/x86_64-linux/ghc-9.12.3/cardano-tx-tools-0.2.3.0/x/tx-sign/build/tx-sign/tx-sign` |
| `cardano-cli` | 10.15.1.0 (git rev 1e6d8228) | `/nix/store/bz64647x6q7ghmdqlax7nb08a9l0gfn6-cardano-cli-exe-cardano-cli-10.15.1.0/bin/cardano-cli` |
| `age` (stock, with `age-plugin-batchpass`) | v1.3.1 | `/nix/store/bx602yqsxz88pr178n8yk1pp7d1vll5k-age-1.3.1/bin/age` |
| `jq` | system | edits the payload |

### Copied from cardano-tx-tools

`payment.skey`, `payment.addr_xsk`, `wrong-payment.skey`,
`unsigned.cbor.hex`, `signed.expected.cbor.hex` and
`witness.expected.hex` are byte-for-byte copies of
`test/fixtures/tx-sign/<name>` at cardano-tx-tools `origin/main`
`1b623b133989d1b1c0d4e52164d26ef76f0d0510`, read with
`git show origin/main:test/fixtures/tx-sign/<name>`. Their own
provenance is that repository's `test/fixtures/tx-sign/fixture-source.md`:
`payment.skey`, `unsigned.cbor.hex`, `signed.expected.cbor.hex` and
`witness.expected.hex` were made by `cardano-cli` (`key-gen`,
`transaction build-raw`, `transaction witness`, `transaction assemble`).
`witness.expected.hex` is the `cardano-cli` witness for `payment.skey`
over `unsigned.cbor.hex`. `payment.addr_xsk` is a deterministic
cardano-addresses 96-byte `addr_xsk` and is unrelated to `payment.skey`.

### Made here

`passphrase` is the vault passphrase, one line (the same text as
`tx-sign/passphrase`).

The vaults, by `tx-sign vault create` with the passphrase on descriptor
9 and scrypt work factor 10:

```sh
mk() { # label key out
  exec 9<passphrase
  tx-sign --network preprod vault create --signing-key-file "$2" \
    --label "$1" --out "$3" --vault-passphrase-fd 9 --vault-work-factor 10
  exec 9<&-
}
mk core_development payment.skey      cli.vault.age
mk addr_xsk_fixture payment.addr_xsk  xsk.vault.age
mk wrong_key        wrong-payment.skey wrong.vault.age   # not committed
for k in cli xsk; do
  AGE_PASSPHRASE="$(head -1 passphrase)" age -d -j batchpass $k.vault.age > $k.payload.json
done
```

`cli.payload.json` and `xsk.payload.json` are what stock `age` decrypts
`cli.vault.age` and `xsk.vault.age` to. The `keyHash` in each was written
by `tx-sign`, not by any code in this repository: `cli` stores
`f3af2802…a826`, the hash `cardano-cli` gave the same key in
`signed.expected.cbor.hex` (required signer); `xsk` stores `62af57d1…20c7`.

The identities whose stored hash is another key's: the `keyHash` of
`wrong_key` (`675947ce…904c`, from the `wrong.vault.age` payload)
written over the hash in each payload, then encrypted by stock `age`
(work factor 18, stock `age`'s fixed default):

```sh
WRONG=$(AGE_PASSPHRASE=… age -d -j batchpass wrong.vault.age \
  | jq -r '.cardanoTxSignVault.identities[].keyHash')
for k in cli xsk; do
  jq --arg h "$WRONG" '.cardanoTxSignVault.identities[].keyHash = $h' \
    $k.payload.json > $k-mismatched.payload.json
  AGE_PASSPHRASE=… age -e -j batchpass -o $k-mismatched.vault.age \
    $k-mismatched.payload.json
done
```

`xsk-unsigned.cbor.hex` is a transaction like `unsigned.cbor.hex` that
requires the `addr_xsk` key (`xsk` identity's key hash), made by
`cardano-cli`; `xsk-witness.expected.hex` is the witness `tx-sign`
(cardano-crypto extended signing) made for it:

```sh
cardano-cli conway transaction build-raw \
  --tx-in 2222222222222222222222222222222222222222222222222222222222222222#0 \
  --tx-out "$(cat out.addr)+1000000" --fee 200000 \
  --required-signer-hash 62af57d18328e645219a713e8f63952beae9dbdd34b91d8c909e20c7 \
  --out-file xsk.tx.body.json
jq -r .cborHex xsk.tx.body.json | tr -d '\n' > xsk-unsigned.cbor.hex
exec 9<passphrase
tx-sign --network preprod witness --tx xsk-unsigned.cbor.hex \
  --vault xsk.vault.age --identity addr_xsk_fixture \
  --vault-passphrase-fd 9 --out xsk-witness.expected.hex
```

(`out.addr` is `cardano-cli conway address build` of
`../payment.vkey` with `--testnet-magic 1`.) The same `tx-sign` over
`unsigned.cbor.hex` with `cli.vault.age` reproduces `witness.expected.hex`
byte for byte, which ties the tool to the `cardano-cli` witness.
