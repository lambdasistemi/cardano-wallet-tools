# Changelog

## [0.1.1](https://github.com/lambdasistemi/cardano-wallet-tools/compare/v0.1.0...v0.1.1) (2026-07-02)


### Features

* age vault signer — cwt vault seal + cwt sign --signing-key-vault ([c83ac54](https://github.com/lambdasistemi/cardano-wallet-tools/commit/c83ac54deed7e6aa384f552c8c239f0a5d71db45))
* bootstrap wallet-core selection scaffold ([62a4008](https://github.com/lambdasistemi/cardano-wallet-tools/commit/62a4008858bd9998b8cb387a6af39365231e838d)), closes [#1](https://github.com/lambdasistemi/cardano-wallet-tools/issues/1)
* CLI scaffold — cwt binary, optparse-applicative, CBOR hex pipeline ([#12](https://github.com/lambdasistemi/cardano-wallet-tools/issues/12)) ([1f5e0fe](https://github.com/lambdasistemi/cardano-wallet-tools/commit/1f5e0feae91e521812e62999d2aa3c3b4ecb2aed)), closes [#10](https://github.com/lambdasistemi/cardano-wallet-tools/issues/10)
* cwt sign — TextEnvelope ed25519 key → attach witness ([#13](https://github.com/lambdasistemi/cardano-wallet-tools/issues/13)) ([ddeebe2](https://github.com/lambdasistemi/cardano-wallet-tools/commit/ddeebe2433fa897d6d0495dd2d6ff1c4ef185a89)), closes [#11](https://github.com/lambdasistemi/cardano-wallet-tools/issues/11)

## Changelog

## Unreleased

### Features

- Bootstrap repository scaffold: flake (haskell.nix, GHC 9.12.3),
  pure `wallet-core` selection algorithms (collateral + strategy),
  justfile / fourmolu / hlint, CI, mkdocs, and the project constitution
  capturing the trust-minimized resolution and collateral-selection
  design (#1).
