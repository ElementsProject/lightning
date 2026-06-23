{ self, ... }:
{
  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    {
      devShells = {
        default = pkgs.mkShell {
          inputsFrom = [ config.packages.default ];
          packages = [ pkgs.uv ];
        };
        postgres = pkgs.mkShell {
          inputsFrom = [ config.packages.cln-postgres ];
          packages = [ pkgs.uv ];
        };
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
          packages = [ pkgs.uv ];
        };
      };
    };
}
