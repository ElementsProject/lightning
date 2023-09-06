{
  description = "A very basic flake";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;
    in {
      packages = rec {
        default = cln;
        cln = pkgs.clightning.overrideAttrs (upstream: rec {
          name = "cln";
          version = "${self.lastModifiedDate}-flake-${self.dirtyShortRev}"; # TODO emulate git describe using CHANGELOG.md or fetch git? impure runCommand?
          makeFlags = [ "VERSION=${version}" "MTIME=${self.lastModifiedDate}" ];
          src = ./.;
        });
      };
      formatter = pkgs.alejandra;
    });
}
