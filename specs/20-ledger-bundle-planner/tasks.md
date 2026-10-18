# Tasks (#20)

## Slice ledger-bundle-planner

- [ ] ledger-sublibrary-builds: CHaP pinned as cardano-tx-tools; `ledger` sublibrary builds in Nix and the dev shell; core library stays ledger-free
- [ ] port-envelopes: unsigned-transaction and witness envelopes, cardano-cli oracle fixtures
- [ ] port-bundle-checks: bundle v1 codec and every offline check, all refusals reported
- [ ] port-witness-signer: ledger detached-witness signer with the tx-tools golden witness, witness assembly
- [ ] port-submit-planner: needed keys, pairing by signature, ordered plan, refusals before send
- [ ] cwt-bundle-check: `cwt bundle check FILE` with summary / named failures, tested in the hosted suite
- [ ] bundle-docs-page: bundle v1 and CIP-0103 mapping page in the MkDocs nav
