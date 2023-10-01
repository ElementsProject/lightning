let
  # Import nixpkgs
  # To see why this is required please look at
  # https://discourse.nixos.org/t/nix-consumes-all-available-memory-evaluating-a-flake-using-recent-nixpkgs/33322
  pkgs = import (fetchTarball {
    url =
      "https://github.com/NixOS/nixpkgs/archive/3476a10478587dec90acb14ec6bde0966c545cc0.tar.gz";
  }) { };
  poetry2nix = pkgs.poetry2nix;

  # Create a Python environment using poetry2nix
  finalEnv = poetry2nix.mkPoetryEnv {
    python = pkgs.python310;
    projectDir = ../../.;
    poetrylock = ../../poetry.lock; # Path to your poetry.lock file
    overrides = poetry2nix.overrides.withDefaults (self: super: {
      cryptography = super.cryptography.overrideAttrs (oldAttrs: rec {
        version = "41.0.4";
        src = pkgs.fetchurl {
          url =
            "https://pypi.io/packages/source/c/cryptography/cryptography-${version}.tar.gz";
          sha256 = "sha256-f+vDCUEl/BJqf2+x9CDQ2mOfPzLLFcj/DcOZfEVJ9Ro=";
        };

        cargoDeps = pkgs.rustPlatform.fetchCargoTarball {
          inherit src;
          sourceRoot = "${oldAttrs.pname}-${version}/src/rust";
          name = "${oldAttrs.pname}-${version}";
          hash = "sha256-oXR8yBUgiA9BOfkZKBJneKWlpwHB71t/74b/5WpiKmw=";
        };

        # cryptography-vectors is in a let so it's not easy to override
        # AssertionError: assert '41.0.4' == '41.0.3'
        doCheck = false;
      });

      attrs = super.attrs.overridePythonAttrs (old: {
        buildInputs = old.buildInputs or [ ]
          ++ [ self.wheel self.hatch-vcs self.hatch-fancy-pypi-readme ];
      });

      protobuf3 = super.protobuf3.overridePythonAttrs (old: {
        buildInputs = old.buildInputs or [ ]
          ++ [ super.setuptools super.wheel ];
      });

      werkzeug = super.werkzeug.overridePythonAttrs
        (old: { buildInputs = old.buildInputs or [ ] ++ [ self.flit-core ]; });

      flask = super.flask.overridePythonAttrs
        (old: { buildInputs = old.buildInputs or [ ] ++ [ self.flit-core ]; });

      execnet = super.execnet.overridePythonAttrs (old: {
        buildInputs = old.buildInputs or [ ] ++ [
          self.hatchling
          self.wheel
          self.hatch-vcs
          self.hatch-fancy-pypi-readme
        ];
      });

      simple-websocket = super.simple-websocket.overridePythonAttrs (old: {
        buildInputs = old.buildInputs or [ ] ++ [ self.setuptools self.wheel ];
      });

      pyln-grpc-proto = super.pyln-grpc-proto.overridePythonAttrs
        (old: { buildInputs = old.buildInputs or [ ] ++ [ self.poetry ]; });

      pytest-custom-exit-code =
        super.pytest-custom-exit-code.overridePythonAttrs (old: {
          buildInputs = old.buildInputs or [ ]
            ++ [ self.setuptools self.wheel ];
        });

      pytest-test-groups = super.pytest-test-groups.overridePythonAttrs (old: {
        buildInputs = old.buildInputs or [ ] ++ [ self.setuptools self.wheel ];
      });

      rpds-py = super.rpds-py.overrideAttrs (old: {
        src = pkgs.fetchurl {
          url =
            "https://files.pythonhosted.org/packages/9e/a8/4a4e5ef90c4c4f27683ce2bb74b9521b5b1d06ac134cd650333fdca0f52c/rpds_py-0.10.4.tar.gz";
          sha256 = "GNX/f70wWh1WQnPp6yLeg6482c1jKf3cjxL2QopxGmo=";
        };
        buildInputs = old.buildInputs ++ [ pkgs.maturin self.gevent self.mypy ];
      });
    });
  };
in with pkgs;
stdenv.mkDerivation {
  name = "git-dev-nix-env";

  buildInputs = [
    gcc
    sqlite
    autoconf
    git
    clang
    libtool
    sqlite
    autoconf
    autogen
    automake
    gnumake
    pkg-config
    gmp
    zlib
    gettext
    libsodium

    # Python dep
    poetry
    python310
    python310Packages.pip
    python310Packages.pytest
    maturin
    finalEnv # Add the poetry environment here

    # optional dev libraries
    ccache

    # debugs libraries
    valgrind

    # Indirected dependencies for running tests
    bitcoind
  ];
}
