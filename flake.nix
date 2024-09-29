{
  description = "Core Lightning (CLN): A specification compliant Lightning Network implementation in C";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

    flake-parts.url = "github:hercules-ci/flake-parts";

    crane.url = "github:ipetkov/crane";

    treefmt-nix.url = "github:numtide/treefmt-nix";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;
      imports = [
        inputs.treefmt-nix.flakeModule
        ./nix/pkgs/flake-module.nix
        ./nix/checks/flake-module.nix
        ./nix/shells.nix
        ./nix/treefmt.nix
      ];
      perSystem =
        {
          config,
          pkgs,
          self',
          system,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (final: prev: { craneLib = (inputs.crane.mkLib pkgs); }) ];
          };
          apps = {
            lightningd = {
              program = "${self'.packages.cln}/bin/lightningd";
            };
            lightning-cli = {
              program = "${self'.packages.cln}/bin/lightning-cli";
            };
            lightning-hsmtool = {
              program = "${self'.packages.cln}/bin/lightning-hsmtool";
            };
            reckless = {
              program = "${self'.packages.cln}/bin/reckless";
            };
          };
        };
    };
}
