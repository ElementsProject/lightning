{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/23.05";
    flake-utils.url = "github:numtide/flake-utils";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    poetry2nix,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;

      inherit
        (poetry2nix.legacyPackages.${system})
        defaultPoetryOverrides
        mkPoetryEnv
        mkPoetryEditablePackage
        ;
    in {
      packages = rec {
        default = cln;
        cln = (pkgs.callPackage ("${nixpkgs}/pkgs/applications/blockchains/clightning") {
          python3 = cln-meta-project; # FIXME neither this nor cln-meta-project.python actually works, but this is conceptually the right thing IIUC
        }).overrideAttrs (upstream: rec {
          name = "cln";
          version = "${self.lastModifiedDate}-flake-${self.dirtyShortRev}"; # TODO emulate git describe using CHANGELOG.md or fetch git? impure runCommand?
          makeFlags = ["VERSION=${version}" "MTIME=${self.lastModifiedDate}"];
          nativeBuildInputs = [ cln-meta-project ] ++ upstream.nativeBuildInputs; # FIXME why does python3 in callPackage not work? work around by placing cln-meta-project's python first
          src = ./.;
          # configureFlags = ["--enable-developer"]; # default flags disable developer and valgrind
          doCheck = true;
          # TODO remove PYTHONPATH
          postPatch = upstream.postPatch +
            ''
            patchShebangs tools/check-*.sh
          '';
        });

        cln-meta-project = mkPoetryEnv {
          projectDir = ./.;

          # See https://github.com/nix-community/poetry2nix/blob/master/docs/edgecases.md
          overrides = defaultPoetryOverrides.extend (self: super:
            lib.genAttrs [
              "protobuf3"
              "pytest-custom-exit-code"
              "pytest-test-groups"
            ] (name:
              super.${name}.overridePythonAttrs (old: {
                nativeBuildInputs = (old.nativeBuildInputs or []) ++ [self.setuptools];
              }))
          // {
            python-bitcoinlib = super.python-bitcoinlib.overridePythonAttrs (old: {
              postPatch = pkgs.python3Packages.bitcoinlib.postPatch; # fixes libssl loading
            });
          });

          # FIXME why does contrib/pyln-grpc-proto have its own poetry.lock?
          # TODO external/lnprototest/
          editablePackageSources = let
            # set PROJECT_ROOT environment variable and use --impure to obtain an
            # editable project directory, e.g. `PROJECT_ROOT=$PWD nix develop --impure`
            impureRoot = builtins.getEnv "PROJECT_ROOT";
            root =
              if impureRoot == ""
              then ./.
              else impureRoot;
          in
            lib.genAttrs [
              "pyln-client"
              "pyln-proto"
              "pyln-grpc-proto"
              "pyln-spec"
              "pyln-testing"
            ] (name: root + "/contrib/${name}");
          preferWheels = builtins.getEnv "PREFER_WHEELS" == "1"; # requires --impure to take effect, quicker to build
        };
      };

      # devShells = {
      #   default = pkgs.mkShell {
      #     buildInputs = [
      #       pkgs.poetry
      #     ];
      #   };
      # };

      formatter = pkgs.alejandra;
    });
}
