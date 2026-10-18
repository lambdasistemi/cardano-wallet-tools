{
  description =
    "Wallet-side UTxO, coin, and collateral selection toolkit";
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      "https://paolino.cachix.org"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "paolino.cachix.org-1:ecmgO3CXdgSWA2cHlm4srknd/cLFMLmK3i3NrzeDFaE="
    ];
  };
  inputs = {
    haskellNix = {
      url =
        "github:input-output-hk/haskell.nix/8b447d7f57d62fab9249f79bb916bc891e29b9d0";
      inputs.hackage.follows = "hackageNix";
    };
    hackageNix = {
      url =
        "github:input-output-hk/hackage.nix/b6b4aa4bd699f743238da45c7f43da5a26a822f7";
      flake = false;
    };
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    lintNixpkgs.url =
      "github:NixOS/nixpkgs/647e5c14cbd5067f44ac86b74f014962df460840";
    flake-parts.url = "github:hercules-ci/flake-parts";
    iohkNix = {
      url =
        "github:input-output-hk/iohk-nix/f444d972c301ddd9f23eac4325ffcc8b5766eee9";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    CHaP = {
      url =
        "github:intersectmbo/cardano-haskell-packages/887d73ce434831e3a67df48e070f4f979b3ac5a6";
      flake = false;
    };
    mkdocs.url = "github:paolino/dev-assets?dir=mkdocs";
  };

  outputs = inputs@{ self, nixpkgs, lintNixpkgs, flake-parts, haskellNix
    , hackageNix, iohkNix, CHaP, mkdocs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      perSystem = { system, ... }:
        let
          pkgs = import nixpkgs {
            overlays = [
              iohkNix.overlays.crypto
              haskellNix.overlay
              iohkNix.overlays.haskell-nix-crypto
            ];
            inherit system;
          };
          lib = pkgs.lib;
          lintPkgs = import lintNixpkgs { inherit system; };
          indexState = "2026-02-17T10:15:41Z";
          # The ledger packages link the iohk-nix crypto libraries; the
          # haddock of the large dependencies is not built.
          fix-libs = { lib, pkgs, ... }: {
            packages.cardano-crypto-praos.components.library.pkgconfig =
              lib.mkForce [ [ pkgs.libsodium-vrf ] ];
            packages.cardano-crypto-class.components.library.pkgconfig =
              lib.mkForce
                [ [ pkgs.libsodium-vrf pkgs.secp256k1 pkgs.libblst ] ];
            packages.cardano-ledger-binary.components.library.doHaddock =
              lib.mkForce false;
            packages.plutus-core.components.library.doHaddock =
              lib.mkForce false;
            packages.plutus-ledger-api.components.library.doHaddock =
              lib.mkForce false;
            packages.plutus-tx.components.library.doHaddock =
              lib.mkForce false;
          };
          project = pkgs.haskell-nix.cabalProject' {
            name = "cardano-wallet-tools";
            src = ./.;
            compiler-nix-name = "ghc9123";
            shell = {
              withHoogle = false;
              tools = {
                cabal = { index-state = indexState; };
              };
              buildInputs = [
                lintPkgs.haskellPackages.cabal-fmt
                lintPkgs.haskellPackages.fourmolu
                lintPkgs.haskellPackages.hlint
                pkgs.just
                pkgs.age
                mkdocs.packages.${system}.from-nixpkgs
              ];
            };
            modules = [
              fix-libs
              { packages.cardano-wallet-tools.flags.werror = true; }
              {
                packages.cardano-wallet-tools.components.tests.spec.build-tools =
                  [ pkgs.age ];
              }
            ];
            inputMap = {
              "https://chap.intersectmbo.org/" = CHaP;
            };
          };
          pkg = project.hsPkgs.cardano-wallet-tools;
          components = pkg.components;
          unitTests = components.tests.spec;
          cwt = components.exes.cwt;
          # Stock age is a test input: the interop examples decrypt vaults
          # with it and fail when it is missing from PATH. cwt is another:
          # the command-line specs run the executable the package builds.
          unitTestsApp = pkgs.writeShellApplication {
            name = "unit-tests";
            runtimeInputs = [ pkgs.age cwt ];
            text = ''exec ${unitTests}/bin/spec "$@"'';
          };
        in {
          packages = {
            default = components.library;
            unit-tests = unitTests;
            cwt = cwt;
          };
          checks = {
            unit = pkg.checks.spec;
          };
          apps = {
            unit-tests = {
              type = "app";
              program = "${unitTestsApp}/bin/unit-tests";
            };
            cwt = {
              type = "app";
              program = "${cwt}/bin/cwt";
            };
          };
          devShells.default = project.shell;
        };
    };
}
