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
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
        };
      };
    };
}
