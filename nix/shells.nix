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
      libeatmydata = pkgs.libeatmydata.overrideAttrs (_: {
        doCheck = false;
        nativeCheckInputs = [ ];
      });
      devTools = [
        libeatmydata
        pkgs.shellcheck
        pkgs.uv
        gsed
      ];
      shellHook = ''
        _cln_stop_regtest_on_exit() {
          if command -v stop_ln >/dev/null 2>&1; then
            stop_ln >/dev/null 2>&1 || true
          fi
        }

        trap _cln_stop_regtest_on_exit EXIT
      ''
      # On Linux, uv uses nixpkgs' Python: the Python uv downloads expects
      # an FHS dynamic loader, so it doesn't run on NixOS.
      # LD_LIBRARY_PATH fixes the following error when running uv pytest tests/:
      #   ImportError: libstdc++.so.6: cannot open shared object file: No such file or directory
      + pkgs.lib.optionalString pkgs.stdenv.isLinux ''
        export UV_PYTHON=${pkgs.python3}/bin/python3
        export UV_PYTHON_DOWNLOADS=never
        export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH"
      '';
    in
    {
      devShells = {
        default = pkgs.mkShell {
          inputsFrom = [ config.packages.default ];
          buildInputs = [ pkgs.openssl ];
          packages = devTools;
          inherit shellHook;
        };
        postgres = pkgs.mkShell {
          inputsFrom = [ config.packages.cln-postgres ];
          buildInputs = [ pkgs.openssl ];
          packages = devTools;
          inherit shellHook;
        };
        rust = pkgs.craneLib.devShell {
          checks = {
            inherit (self.checks.${system}) rust;
          };
          packages = devTools;
          inherit shellHook;
        };
      };
    };
}
