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
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
        };
      };
    };
}
