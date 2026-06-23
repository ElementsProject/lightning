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
          buildInputs = [ pkgs.openssl ];
          packages = [ pkgs.uv ];
          # On Linux, uv uses nixpkgs' Python: the Python uv downloads expects
          # an FHS dynamic loader, so it doesn't run on NixOS.
          # LD_LIBRARY_PATH fixes the following error when running uv pytest tests/:
          #   ImportError: libstdc++.so.6: cannot open shared object file: No such file or directory
          shellHook = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
            export UV_PYTHON=${pkgs.python3}/bin/python3
            export UV_PYTHON_DOWNLOADS=never
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH"
          '';
        };
        postgres = pkgs.mkShell {
          inputsFrom = [ config.packages.cln-postgres ];
          buildInputs = [ pkgs.openssl ];
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
