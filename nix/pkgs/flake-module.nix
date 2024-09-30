{ self, ... }:
{
  perSystem =
    { pkgs, config, ... }:
    {
      packages = rec {
        # This package depends on git submodules so use a shell command like 'nix build .?submodules=1'.
        cln = pkgs.callPackage ./default.nix { inherit self pkgs config; };
        cln-postgres = pkgs.callPackage ./default.nix {
          inherit self pkgs config;
          postgresSupport = true;
        };
        rust = pkgs.callPackage ./rust.nix { craneLib = pkgs.craneLib; };
        default = cln;
      };
    };
}
