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
