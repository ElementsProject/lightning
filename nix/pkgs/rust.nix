{
  pkgs,
  lib,
  craneLib,
  ...
}:
let
  version = builtins.readFile ../../.version;
  src = lib.cleanSourceWith {
    src = ../../.;
    filter = path: type: (lib.hasSuffix "\.proto" path) || (craneLib.filterCargoSources path type);
  };
in
craneLib.buildPackage {
  pname = "rust";
  inherit src version;
  strictDeps = true;
  nativeBuildInputs = with pkgs; [ protobuf ];
}
