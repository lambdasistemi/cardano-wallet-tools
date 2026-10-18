# Tasks (#20)

## Slice ledger-bundle-planner

- [x] ledger-sublibrary-builds: CHaP pinned as cardano-tx-tools; `ledger` sublibrary builds in Nix and the dev shell; core library stays ledger-free
- [x] port-envelopes: unsigned-transaction and witness envelopes, cardano-cli oracle fixtures
- [x] port-bundle-checks: bundle v1 codec and every offline check, all refusals reported
- [x] port-witness-signer: ledger detached-witness signer with the tx-tools golden witness, witness assembly
- [x] port-submit-planner: needed keys, pairing by signature, ordered plan, refusals before send
- [x] cwt-bundle-check: `cwt bundle check FILE` with summary / named failures, tested in the hosted suite
- [x] bundle-docs-page: bundle v1 and CIP-0103 mapping page in the MkDocs nav
