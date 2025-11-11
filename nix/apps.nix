{ ... }:
{
  perSystem =
    {
      config,
      pkgs,
      system,
      self',
      ...
    }:
    {
      apps = {
        lightningd = {
          program = "${self'.packages.cln}/bin/lightningd";
          meta.description = "Core Lightning daemon";
        };
        lightning-cli = {
          program = "${self'.packages.cln}/bin/lightning-cli";
          meta.description = "Core Lightning command line interface";
        };
        lightning-hsmtool = {
          program = "${self'.packages.cln}/bin/lightning-hsmtool";
          meta.description = "Core Lightning HSM tool";
        };
        reckless = {
          program = "${self'.packages.cln}/bin/reckless";
          meta.description = "Core Lightning reckless tool";
        };
      };
    };
}
