# shellcheck shell=bash

set unstable := true

# List available recipes
default:
    @just --list

# Build all components (-O0 for fast dev builds)
build:
    cabal build -O0 all

# Run the unit test suite
unit:
    cabal test -O0 all

# Format Haskell and Cabal files
format:
    #!/usr/bin/env bash
    set -euo pipefail
    find . -type f -name '*.hs' \
      -not -path '*/dist-newstyle/*' \
      -exec fourmolu -i {} +
    cabal-fmt -i cardano-wallet-tools.cabal

# Check Haskell and Cabal formatting
format-check:
    #!/usr/bin/env bash
    set -euo pipefail
    find . -type f -name '*.hs' \
      -not -path '*/dist-newstyle/*' \
      -exec fourmolu -m check {} +
    cabal-fmt -c cardano-wallet-tools.cabal

# Run hlint
hlint:
    #!/usr/bin/env bash
    set -euo pipefail
    find . -type f -name '*.hs' \
      -not -path '*/dist-newstyle/*' \
      -exec hlint {} +

# Hackage-readiness check
cabal-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cabal check \
      --ignore=missing-upper-bounds \
      --ignore=no-modules-exposed \
      --ignore=option-o2

# Full local CI mirror
ci: build unit format-check hlint cabal-check

# Build the documentation site
build-docs:
    mkdocs build --strict

# Serve the documentation locally
serve-docs:
    mkdocs serve

# Deploy the documentation
deploy-docs:
    mkdocs gh-deploy --force
