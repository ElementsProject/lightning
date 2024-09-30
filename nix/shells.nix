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
        default = pkgs.mkShell { inputsFrom = [ config.packages.default ]; };
        postgres = pkgs.mkShell { inputsFrom = [ config.packages.cln-postgres ]; };
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
        };
      };
    };
}
