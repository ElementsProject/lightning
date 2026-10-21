{
  description = "Core Lightning (CLN): A specification compliant Lightning Network implementation in C";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    crane.url = "github:ipetkov/crane";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    self.submodules = true;
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
        ./nix/apps.nix
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
            overlays = [
              (final: prev: { craneLib = (inputs.crane.mkLib pkgs); })
              # crates.io now 403s any
              # User-Agent starting with "curl/", which is exactly what
              # nixpkgs' fetchurl sends
              # (`curl/$curlVersion Nixpkgs/$nixpkgsVersion`), so every
              # crate tarball that is not already in cache.nixos.org fails
              # to fetch.  Send a UA it accepts.  fetchurl outputs are
              # fixed-output, so this changes no store path -- only whether
              # the fetch succeeds.
              (final: prev: {
                fetchurl =
                  args:
                  prev.fetchurl (
                    args
                    // {
                      curlOptsList = (args.curlOptsList or [ ]) ++ [
                        "--user-agent"
                        "Nixpkgs fetchurl (Core Lightning reprobuild)"
                      ];
                    }
                  );
              })
            ];
          };
        };
    };
}
