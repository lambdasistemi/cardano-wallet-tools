# Plan: FIDO2 vault (issue #21)

## Strategy

The Haskell `age` package (0.0.1.0) has no plugin support but exports
the pieces an age file is made of: `Crypto.Age.Header` (stanzas, header
builder/parser, `computeHeaderMac`), `Crypto.Age.Key` (file key, payload
key nonce, payload key) and the payload chunk modules. `cwt` gets a
kind-neutral age plugin client that wraps/unwraps the file key through
the plugin process and frames a standard binary age v1 file around the
stanzas it returns. The FIDO2 vault kind sits on that client beside
`Vault.Scrypt`, reusing `Vault.Payload` (payload, `signerFromKey`) and
`Vault.File` (exclusive 0600 create). The CLI for the new kind lives in
its own module, so `Cli.Vault` and every module from #19 keep their
exported API unchanged; `app/Main.hs` only gains dispatch entries.

## Constraints

- No change to the exported API of `Vault.Payload`, `Vault.Scrypt`,
  `Vault.File`, `Vault.Passphrase`, `Cli.Vault` (PR #22 contract).
  Additive exports only; anything else is a question to the ticket owner.
- #20 edits the same cabal file, `flake.nix` and `app/Main.hs` in
  parallel: keep edits additive and local.
- The real plugin is a nix runtime dependency of the `cwt` package and
  app; tests never reach the real plugin or a real authenticator.
- The fake plugin is built by this repository's nix and cabal builds,
  with no network, and is available to `cabal test` in the dev shell,
  `nix run .#unit-tests` and `checks.unit` alike.
- Every new obligation-shaped test runs in an existing hosted step
  (`nix run .#unit-tests`, `checks.unit`); no new local-only check.
- Plugin stdio is a live boundary: protocol tests drive a real child
  process, not an in-process mock of one.
- Fourmolu, hlint and `cabal check` clean; `-Werror` builds.

## Live boundaries

- `cwt` ↔ plugin process over stdin/stdout (fake in CI, real on hardware).
- stock `age` ↔ the same fake plugin (interop in CI).
- plugin ↔ terminal for PIN/touch (hardware run only).

## Slices

One behaviour slice, `fido2-vault`, OWNER topology, one final commit.
Checkpoints: RED bundle; acceptance line 1 (protocol + fake plugin);
line 2 (two recipients, golden witness, interop); line 3 (rekey);
pre-push. Hardware lines 4–5 follow on the pushed head via the operator.

## Selected test paths (the gate filters on these)

`fido2/protocol`, `fido2/two recipients`, `fido2/rekey`,
`fido2/golden witness`, `fido2/stock age` — hspec describe paths, run
with `--fail-on=empty,pending`.
