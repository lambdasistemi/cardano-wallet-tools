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
    mkdocs.url = "github:paolino/dev-assets?dir=mkdocs";
  };

  outputs = inputs@{ self, nixpkgs, lintNixpkgs, flake-parts, haskellNix
    , hackageNix, mkdocs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      perSystem = { system, ... }:
        let
          pkgs = import nixpkgs {
            overlays = [ haskellNix.overlay ];
            inherit system;
          };
          lib = pkgs.lib;
          lintPkgs = import lintNixpkgs { inherit system; };
          indexState = "2026-02-17T10:15:41Z";
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
                mkdocs.packages.${system}.from-nixpkgs
              ];
            };
            modules = [
              { packages.cardano-wallet-tools.flags.werror = true; }
            ];
          };
          pkg = project.hsPkgs.cardano-wallet-tools;
          components = pkg.components;
          unitTests = components.tests.spec;
          cwt = components.exes.cwt;
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
              program = "${unitTests}/bin/spec";
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
