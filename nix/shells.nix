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
          buildInputs = [
            pkgs.stdenv.cc.cc.lib
            pkgs.uv
          ];
          # this fixes the following error when running uv pytest tests/:
          #   ImportError: libstdc++.so.6: cannot open shared object file: No such file or directory
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH"
          '';
        };
        postgres = pkgs.mkShell { inputsFrom = [ config.packages.cln-postgres ]; };
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
        };
      };
    };
}
