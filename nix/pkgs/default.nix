{
  self,
  lib,
  pkgs,
  config,
  postgresSupport ? false,
}:
with pkgs;
let
  version = builtins.readFile ../../.version;
  py3 = python3.withPackages (p: [
    p.grpcio-tools
    p.mako
  ]);
in
stdenv.mkDerivation {
  name = "cln";
  src = ../../.;
  inherit version;
  makeFlags = [
    "VERSION=${version}"
    "MTIME=${self.lastModifiedDate}"
    "NO_PYTHON=1"
  ];

  # when building on darwin we need cctools to provide the correct libtool
  # as libwally-core detects the host as darwin and tries to add the -static
  # option to libtool, also we have to add the modified gsed package.
  nativeBuildInputs =
    [
      autoconf
      autogen
      automake
      gettext
      gitMinimal
      postgresql
      libtool
      lowdown
      pkgconf
      py3
      unzip
      which
    ]
    ++ lib.optionals postgresSupport [ postgresql ]
    ++ lib.optionals stdenv.isDarwin [
      cctools
      darwin.autoSignDarwinBinariesHook
    ];

  buildInputs = [
    gmp
    jq
    libsodium
    sqlite
    zlib
  ];

  # this causes some python trouble on a darwin host so we skip this step.
  # also we have to tell libwally-core to use sed instead of gsed.
  postPatch =
    if !stdenv.isDarwin then
      ''
        patchShebangs \
          tools/generate-wire.py \
          tools/update-mocks.sh \
          tools/mockup.sh \
          tools/fromschema.py \
          devtools/sql-rewrite.py
      ''
    else
      ''
        substituteInPlace external/libwally-core/tools/autogen.sh --replace gsed sed && \
        substituteInPlace external/libwally-core/configure.ac --replace gsed sed
      '';

  configureFlags = [ "--disable-valgrind" ];

  enableParallelBuilding = true;

  # workaround for build issue, happens only x86_64-darwin, not aarch64-darwin
  # ccan/ccan/fdpass/fdpass.c:16:8: error: variable length array folded to constant array as an extension [-Werror,-Wgnu-folding-constant]
  #                 char buf[CMSG_SPACE(sizeof(fd))];
  env.NIX_CFLAGS_COMPILE = lib.optionalString (
    stdenv.isDarwin && stdenv.isx86_64
  ) "-Wno-error=gnu-folding-constant";

  postInstall = ''
    cp ${config.packages.rust}/bin/cln-grpc $out/libexec/c-lightning/plugins
  '';

  meta = with lib; {
    description = "Core Lightning (CLN): A specification compliant Lightning Network implementation in C";
    homepage = "https://github.com/ElementsProject/lightning";
    license = licenses.mit;
    platforms = platforms.linux ++ platforms.darwin;
  };
}
