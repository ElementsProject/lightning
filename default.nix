let
  # Import nixpkgs
  pkgs = import <nixpkgs> { };

  # Import poetry2nix and its functions
  poetry2nix = pkgs.poetry2nix;

  # Create a Python environment using poetry2nix
  baseEnv = poetry2nix.mkPoetryEnv {
    python = pkgs.python310;
    projectDir = ./.;
    poetrylock = ./poetry.lock; # Path to your poetry.lock file
  };
  finalEnv = baseEnv.overrideAttrs (oldAttrs: {
    buildInputs = oldAttrs.buildInputs ++ [ pkgs.python310Packages.hatchling ];
  });
in
with pkgs;
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
    baseEnv # Add the poetry environment here

    # optional dev libraries
    ccache

	# debugs libraries
	valgrind
    ];
    shellHook = ''
    	# Tells pip to put packages into $PIP_PREFIX instead of the usual locations.
    	# See https://pip.pypa.io/en/stable/user_guide/#environment-variables.
    	export PIP_PREFIX=$(pwd)/_build/pip_packages
    	export PYTHONPATH="$PIP_PREFIX/${pkgs.python3.sitePackages}:$PYTHONPATH"
    	export PATH="$PIP_PREFIX/bin:$PATH"
   	unset SOURCE_DATE_EPOCH
	poetry config experimental.new-installer false

<<<<<<< HEAD
   '';
}


=======
    # Indirected dependencies for running tests
    bitcoind
  ];
}
>>>>>>> 9303cc6dd (fixup! build: add a simple nix dev shell)
