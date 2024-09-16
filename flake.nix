{
  description = "Core Lightning (CLN): A specification compliant Lightning Network implementation in C";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
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
      perSystem =
        {
          config,
          pkgs,
          self',
          ...
        }:
        {
          packages = rec {
            # This package depends on git submodules so use a shell command like 'nix build .?submodules=1'.
            cln = pkgs.callPackage nix/pkgs/default.nix { inherit self pkgs; };
            default = cln;
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
          checks = {
            cln = self'.packages.cln;
          };
          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
