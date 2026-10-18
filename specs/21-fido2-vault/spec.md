# Spec: FIDO2 vault via the age plugin protocol (issue #21)

Parent: epic #18. Base: `main` at `d48385b` (vault v1, PR #22).
Class: changes behaviour (new vault kind, new commands, a protocol client).

## User stories

- **fido2-create** — An operator with one or more FIDO2 authenticators
  runs `cwt vault create --fido2 --recipient <age1fido2-hmac1…> [...]
  --signing-key <payment.skey> --out <vault>` and gets a vault file that
  only those authenticators can open.
- **fido2-sign** — The operator runs `cwt sign --fido2-vault <vault>
  --fido2-identity <identity file>` with a tx on stdin; the authenticator
  is asked (PIN, touch) through the terminal, and the signed tx is on
  stdout, byte-identical to signing with the plaintext key.
- **fido2-rekey** — An operator who lost one authenticator runs
  `cwt vault rekey --vault <old> --fido2-identity <surviving identity>
  --recipient <new set...> --out <new>`; the new vault holds the same
  key, opens with the new set only, and the old file is untouched.

## Requirements

- **plugin-client-protocol** — `cwt` is the client side of the age plugin
  stdio protocol (C2SP `age-plugin.md`): it runs `age-plugin-<name>
  --age-plugin=recipient-v1` to wrap a file key and
  `--age-plugin=identity-v1` to unwrap one, `<name>` taken from the
  recipient/identity encoding as age does. It answers every plugin
  command the spec defines for its phase (`msg`, `request-public`,
  `request-secret`, `confirm`, `recipient-stanza`/`file-key`, `error`,
  `done`) and answers `unsupported` to any other command without failing.
- **plugin-ui-is-terminal** — In `cwt`, plugin messages go to the
  terminal (stderr), secrets are read from `/dev/tty` with echo off, and
  no secret, file key or signing key is printed.
- **fido2-vault-shape** — A FIDO2 vault is a standard binary age v1 file
  whose stanzas all come from `fido2-hmac` recipients (one or more, no
  scrypt, no other kind); its plaintext is the vault v1 payload
  (`encodeV1Payload`). `create --fido2` refuses a recipient that is not a
  `fido2-hmac` recipient, and refuses zero recipients.
- **fido2-open-any-one** — A vault sealed to N FIDO2 recipients opens with
  the identity of any single one of them.
- **fido2-open-refusals** — Opening with an identity that matches no
  stanza, a scrypt vault, a corrupt file or a plugin error all answer the
  single opening refusal (`VaultNotOpened`); a missing plugin binary is
  its own refusal naming the binary.
- **fido2-sign-through-signer** — Signing from a FIDO2 vault uses
  `signerFromKey`; the witness for the golden tx equals
  `test/fixtures/vault/golden/witness.expected.hex` byte for byte (same
  bytes as cardano-tx-tools `test/fixtures/tx-sign/witness.expected.hex`).
- **rekey-same-key-new-set** — `rekey` opens with one identity and writes
  a new vault to the given recipient set, holding the same signing key;
  a recipient absent from the new set cannot open it; the source file is
  byte-identical before and after.
- **vault-file-rules** — `create --fido2` and `rekey` write through
  `Vault.File` (exclusive, mode 0600, no-follow, removed on failed write);
  an existing `--out` (including `--out` equal to `--vault`) is refused
  and untouched; nothing is written when the plugin fails.
- **age-interop** — A vault made by `cwt` decrypts with stock `age -d -i
  <identity>`, and a v1 payload encrypted by stock `age -r <recipient>`
  opens with `cwt`; in CI both run against the fake plugin, on real
  hardware against `age-plugin-fido2-hmac`.
- **plugin-runtime-dependency** — The nix-built `cwt` (`.#cwt` package
  and app) finds `age-plugin-fido2-hmac` without the user installing it.
- **fake-plugin** — Tests use a fake plugin built from this repository
  that speaks the real stdio protocol, installed under the
  `age-plugin-fido2-hmac` name only on the test's own PATH. Each fake
  identity unwraps only the stanzas wrapped for its own recipient. It can
  be steered to emit `msg`, `request-secret`, an unknown command and an
  `error`, so the client's handling of each is exercised.
- **no-silent-skip** — No FIDO2 example is pending or skipped when the
  fake plugin or stock `age` is absent; absence fails the example.

## Rejection behaviour

Refusals are values rendered to one line on stderr with non-zero exit;
none contains a secret, a file key or key bytes.

## Observable success (acceptance, issue #21)

1. Protocol and vault tests pass against the fake plugin in `just ci`.
2. A vault encrypted to two FIDO2 recipients opens with each one alone.
3. `rekey` from a two-recipient vault: a new recipient opens the new
   vault, a removed one does not, the signing key is unchanged.
4. A vault made by `cwt` with a real key decrypts with stock
   `age -d -i <plugin identity>` (operator, hardware).
5. One manual signing run on a real authenticator is recorded in the PR
   (operator, hardware).

Lines 1–3 are proved by hosted CI; lines 4–5 by the operator running
`handoffs/hardware-run.md`, output pasted in the PR.

## Non-goals

Mixing scrypt and FIDO2 recipients; tx-sign multi-identity payloads in
FIDO2 vaults; generating FIDO2 credentials (the plugin does that);
other age plugins beyond what the kind-neutral client gives for free.
