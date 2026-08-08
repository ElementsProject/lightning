{ self, ... }:
{
  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    let
      gsed = pkgs.writeShellScriptBin "gsed" ''
        exec ${pkgs.gnused}/bin/sed "$@"
      '';
      devTools = [
        pkgs.uv
        gsed
      ];
    in
    {
      devShells = {
        default = pkgs.mkShell {
          inputsFrom = [ config.packages.default ];
          packages = devTools;
        };
        postgres = pkgs.mkShell {
          inputsFrom = [ config.packages.cln-postgres ];
          packages = devTools;
        };
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
          packages = devTools;
        };
      };
    };
}
