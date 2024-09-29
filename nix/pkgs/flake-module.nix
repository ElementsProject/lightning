{ self, ... }:
{
  perSystem =
    { pkgs, config, ... }:
    {
      packages = rec {
        # This package depends on git submodules so use a shell command like 'nix build .?submodules=1'.
        cln = pkgs.callPackage ./default.nix { inherit self pkgs config; };
        rust = pkgs.callPackage ./rust.nix { craneLib = pkgs.craneLib; };
        default = cln;
      };
    };
}
