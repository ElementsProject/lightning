{ inputs, self, ... }:
{
  perSystem =
    { pkgs, config, ... }:
    let
      advisory-db = inputs.advisory-db;
    in
    {
      checks = {
        cln = config.packages.cln;
        cln-postgres = config.packages.cln-postgres;
        rust = config.packages.rust;
        cargo-audit = pkgs.craneLib.cargoAudit {
          src = ../../.;
          inherit advisory-db;
        };
        formatting = config.treefmt.build.check self;
      };
    };
}
