# Tasks: FIDO2 vault (issue #21)

## Slice fido2-vault

- [X] age-plugin-client — `Vault.Plugin` runs recipient-v1 and identity-v1 over stdio, relays interaction through `PluginUi`, answers `unsupported`, frames binary age v1 around plugin stanzas.
- [X] fake-fido2-plugin — repository-built fake speaking the real protocol, recipient-isolated, steerable; on the test PATH in `cabal test`, `nix run .#unit-tests` and `checks.unit`.
- [X] fido2-vault-kind — `Vault.Fido2` seal to ≥ 1 fido2-hmac recipients, open with any one identity, opening refusals.
- [X] fido2-rekey — `rekeyFido2Vault` and `cwt vault rekey`: same key, new set, old file untouched, exclusive 0600 out.
- [X] cwt-fido2-commands — `cwt vault create --fido2`, `cwt sign --fido2-vault/--fido2-identity`, terminal plugin UI.
- [X] fido2-golden-witness — FIDO2-vault signing equals the golden witness byte for byte.
- [X] stock-age-interop — cwt-made vault decrypts with stock `age -d -i`, stock-`age`-made vault opens with `cwt` (fake plugin).
- [X] plugin-nix-runtime-dependency — nix-built `cwt` finds `age-plugin-fido2-hmac`.
- [X] hardware-run-script — `handoffs/hardware-run.md` and PR body section for acceptance lines 4–5.
