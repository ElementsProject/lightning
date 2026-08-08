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
      '';
    in
    {
      devShells = {
        default = pkgs.mkShell {
          inputsFrom = [ config.packages.default ];
          packages = devTools;
          inherit shellHook;
        };
        postgres = pkgs.mkShell {
          inputsFrom = [ config.packages.cln-postgres ];
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
