{
  self,
  lib,
  pkgs,
  config,
  postgresSupport ? false,
  # Release mode.
  #
  # The release artifacts are built from *this* derivation, as a static and/or
  # cross variant of it, rather than from a second release-only derivation that
  # could drift from what `nix build .#cln` produces.  `release = true` switches
  # on everything the release needs and nothing an ordinary build wants:
  #
  #   * version/mtime come from the driver (REPRO_VERSION / REPRO_MTIME),
  #     not from `.version` and `self.lastModifiedDate` -- bit-identity
  #     across two runs of different checkouts depends on it;
  #   * one `make install` builds the Rust plugins itself,
  #     so the crane side-build and NO_PYTHON=1 are off and cargo is fed
  #     an offline vendor dir instead of the network;
  #   * -static-pie on the compiler driver, with PIE_LDFLAGS overridden
  #     (the Makefile's trailing -pie turns -static-pie into
  #     a *dynamic* link);
  #   * strip --strip-all on every shipped ELF.
  release ? false,
  releaseVersion ? null,
  releaseMtime ? null,
  # The row's arch token from nix/release-rows (amd64, arm64,
  # armhf).  It only names the artifact; which package set the
  # row builds under is decided by the caller.
  releaseArch ? null,
}:
with pkgs;
let
  version = if release then releaseVersion else builtins.readFile ../../.version;
  mtime = if release then releaseMtime else self.lastModifiedDate;
  # Build-machine tools.  `with pkgs;` bypasses callPackage's splicing, so
  # under pkgsStatic a bare `cargo`/`python3` is the *static* build of that
  # tool (cargo's is even marked broken) rather than the native one that
  # targets musl.  For a native package set buildPackages == pkgs, so this
  # is a no-op off the release path.
  bp = pkgs.buildPackages;
  py3 = bp.python3.withPackages (p: [
    p.grpcio-tools
    p.mako
  ]);
  # Offline cargo vendor dir.  A Nix sandbox has no network, so "fetches are
  # allowed as long as the lockfile pins them" becomes a vendor derivation keyed
  # on Cargo.lock: the same inputs, pinned the same way, fetched earlier.
  cargoVendor = buildPackages.rustPlatform.importCargoLock {
    lockFile = ../../Cargo.lock;
  };
  rustTarget = stdenv.hostPlatform.rust.rustcTarget;
  rustTargetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] rustTarget);
  # The cross rows.
  #
  # `canExecute` is nixpkgs' name for a fact this build had to discover the
  # hard way: the build machine cannot run what a cross row produces, and
  # CLN's build *does* run its own output in five places (the configurator's
  # test programs, tools/headerversions, `plugins/sql --print-docs`, ...).
  # On the host those had been running silently under the kernel's binfmt
  # registration -- which is `F`-flagged here, so it reaches inside the Nix
  # sandbox too.  A release build must not depend on how the captain's
  # kernel happens to be configured, so the emulator comes from *this
  # closure*: `hostPlatform.emulator buildPackages` is the qemu-user binary
  # nixpkgs would use, pinned by the same revision as everything else.
  crossRow = !(stdenv.buildPlatform.canExecute stdenv.hostPlatform);
  emulator = stdenv.hostPlatform.emulator bp;
  # How a release binary is linked lives in static-pie.nix, imported here and
  # by vls.nix so the signer links exactly as Core Lightning does.  That file
  # carries the reasoning for each wrapper; these are just the names it exports.
  inherit (import ./static-pie.nix { inherit pkgs lib; })
    arm32
    staticPieFlags
    staticPieCc
    releaseCc
    rustStaticPieCc
    noRpathEnv
    ;
  # The row's libpq, bound once.  On arm32, postgres cannot even
  # *configure*: its "whether the C compiler works" test links an
  # executable, and nixpkgs' `pie` hardening plus pkgsStatic's `-static`
  # make gcc pick the non-PIE crtbeginT.o for a PIE link -- "relocation
  # R_ARM_MOVW_ABS_NC against a local symbol can not be used when making a
  # shared object".  Isolated to the hardening flag on a one-line program:
  # `pie` on fails, `pie` off links, and a command-line `-no-pie` does not
  # rescue it.  Only the library's own build is affected; our binaries still
  # link static-pie, via `staticPieCc` above.
  #
  # Bound here rather than inline in buildInputs because `POSTGRES_LDLIBS`
  # below needs the *same* derivation: referring to the un-overridden
  # `libpq` there pulled both into the closure, and the build then died on
  # the one this override exists to avoid.
  libpqRow =
    if arm32 then
      libpq.overrideAttrs (o: {
        hardeningDisable = (o.hardeningDisable or [ ]) ++ [ "pie" ];
      })
    else
      libpq;

  # when building on darwin we need cctools to provide the correct libtool
  # as libwally-core detects the host as darwin and tries to add the -static
  # option to libtool, also we have to add the modified gsed package.
  nativeInputs =
    with bp;
    [
      autoconf
      autogen
      automake
      gettext
      gitMinimal
      libtool
      lowdown
      pkgconf
      py3
      unzip
      which
    ]
    ++ lib.optionals (postgresSupport && !release) [
      pkgs.libpq
      pkgs.libpq.pg_config
    ]
    ++ lib.optionals release [
      cargo
      rustc
      protobuf
      file
      # configure needs a jq it can *run* ("*** We need jq!"); the one in
      # buildInputs is the musl-static target build.  The Alpine builder
      # same requirement for the Alpine builder.
      jq
      # A build-platform C compiler reachable as plain `cc`.  cargo compiles
      # build scripts and proc macros *for the build machine* and asks rustc
      # for its default linker, which is `cc`; the cross stdenv only puts
      # `x86_64-unknown-linux-musl-gcc` on PATH, so every build script fails
      # with "linker `cc` not found".  Same class as CC_FOR_BUILD below.
      stdenv.cc
    ]
    ++ lib.optionals stdenv.isDarwin [
      cctools
      darwin.autoSignDarwinBinariesHook
    ];

  hostInputs = [
    gmp
    jq
    libsodium
    sqlite
    zlib
  ]
  ++ lib.optionals (postgresSupport && release) [
    libpqRow
    # libpq.a is linked, not loaded, so *its* dependencies become ours:
    # nixpkgs records them in libpq's own `LIBS` as
    # `-lpgcommon -lpgport -lssl -lcrypto -lz -lm`.  zlib is already here;
    # OpenSSL is not, and libpq propagates only its `-dev` output (whose
    # `lib/` holds nothing but pkgconfig), so without this the link path
    # has no `libssl.a`/`libcrypto.a` at all.
    openssl
  ];

  # Everything make is told on the release path except version and mtime,
  # which are per-release labels; both are listed in the input manifest.
  releaseMakeFlags =
    lib.optionals release [
      "RUST_PROFILE=release"
      "PIE_LDFLAGS=-static-pie"
      "TARGET=${rustTarget}"
      # $(AR) has no assignment in the Makefile, so it would fall back to
      # make's built-in `ar` -- the *build* machine's, which cannot index a
      # foreign archive.  Stated rather than left to the stdenv's exported AR.
      "AR=${stdenv.cc.targetPrefix}ar"
    ]
    ++ lib.optionals (release && crossRow) [
      # external/Makefile switches to --host/--build only when BUILD is set;
      # without it libwally/libbacktrace configure as if native and their own
      # run-tests decide wrong.  CC_FOR_BUILD is there because
      # cdump-enumstr is a build-machine program (it is *run* to generate
      # source), so it must not be cross-compiled.
      "BUILD=${stdenv.buildPlatform.config}"
      "MAKE_HOST=${stdenv.hostPlatform.config}"
      "CC_FOR_BUILD=cc"
    ];

  configureFlags = [ "--disable-valgrind" ] ++ lib.optionals release [ "--prefix=/usr/local" ];

  # Environment the release build needs set; also listed in the input
  # manifest, since each of these moves release bytes.
  releaseEnv = {
    NIX_OUTPATH_USED_AS_RANDOM_SEED = "cln-release";
  }
  // noRpathEnv;
  # Stated once so the input manifest can list it: these reach every Rust
  # artifact's bytes, and a reviewer who does not read Nix should see a diff
  # when they change.  The vendor path itself is deliberately *not*
  # in the manifest line -- remapping is what stops it mattering -- but its
  # presence is.
  vendorRemap = "--remap-path-prefix=${cargoVendor}=/home/clightning/vendor";
  rustflagsShape = "--remap-path-prefix=$NIX_BUILD_TOP=/home/clightning --remap-path-prefix=<cargo-vendor>=/home/clightning/vendor -C link-arg=-Wl,--build-id=sha1";

in
stdenv.mkDerivation {
  name = "cln";
  src = ../../.;
  inherit version;
  makeFlags = [
    "VERSION=${version}"
    "MTIME=${mtime}"
  ]
  ++ lib.optionals (!release) [ "NO_PYTHON=1" ]
  ++ releaseMakeFlags;

  nativeBuildInputs = nativeInputs;
  buildInputs = hostInputs;

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
          devtools/sql-rewrite.py \
          devtools/blockreplace.py
      ''
    else
      ''
        substituteInPlace external/libwally-core/tools/autogen.sh --replace gsed sed && \
        substituteInPlace external/libwally-core/configure.ac --replace gsed sed
      '';

  # The unpacked source directory is named after the *source
  # store path* (`<tree-hash>-source`), so its name changes with any tree
  # change, shipped or not.  It reaches the shipped bytes through rustc panic
  # locations, DWARF `comp_dir` and -- once a -ffile-prefix-map names it --
  # `CCAN_CFLAGS` in the generated `ccan/config.h`; the latter two move the
  # link-time `--build-id=sha1` and are then stripped away, so a build-id is
  # all that is left to see.  A constant name removes all of them, and the
  # $NIX_BUILD_TOP map below then yields a constant `/home/clightning/source`.
  ${if release then "postUnpack" else null} = ''
    mv -- "$sourceRoot" source
    export sourceRoot=source
  '';

  inherit configureFlags;

  # CLN's ./configure is hand-rolled, not autotools: it rejects the flags
  # nixpkgs' configurePhase adds for a static cross build
  # (`--enable-static --disable-shared`, `--build=`, `--host=`) with
  # "Unknown option".  Suppress them and hand it the one prefix it wants;
  # `prefix` (not a configureFlags entry) so nixpkgs emits it exactly once.
  # The tarball must unpack over `/`, so the release installs to a DESTDIR
  # with --prefix=/usr/local -- where CLN has always documented its binaries,
  # and where a hand-built `make install` puts them.  A release tarball is not
  # the place to move a project's install directory.
  # `prefix` is not the knob to use here: nixpkgs feeds it to configure
  # *and* runs `mkdir -p "$prefix"` in installPhase, so an absolute prefix
  # fails with "mkdir: cannot create directory: Permission denied".
  # Suppress nixpkgs' own --prefix and pass ours in configureFlags; $out
  # stays the prefix nixpkgs creates, and DESTDIR + --prefix=/usr/local gives
  # a tarball that unpacks over `/`.
  dontAddPrefix = release;
  dontAddStaticConfigureFlags = release;
  configurePlatforms = [ ];

  # ./configure detects Python via `uv` (configure:default_python), which is not
  # part of this derivation. Point it at the python3 we already provide so the
  # codegen steps that call $(PYTHON) (e.g. devtools/blockreplace.py) work.
  preConfigure = ''
    export PYTHON=python3
  ''
  + lib.optionalString release ''
    export PYTEST=
    export SOURCE_DATE_EPOCH LANG=C LC_ALL=C TZ=UTC

    # cargo, offline, against the vendored crates.
    export CARGO_HOME=$NIX_BUILD_TOP/cargo-home
    mkdir -p $CARGO_HOME
    cat > $CARGO_HOME/config.toml <<EOF
    [source.crates-io]
    replace-with = "vendored-sources"
    [source.vendored-sources]
    directory = "${cargoVendor}"
    EOF
    export CARGO_BUILD_TARGET=${rustTarget}
    export CARGO_TARGET_${rustTargetEnv}_LINKER=${rustStaticPieCc}/bin/${stdenv.cc.targetPrefix}rust-cc
    # The vendor dir is remapped too.  It is ~500 panic-location
    # strings per plugin, and its store path is input-addressed, so it moves
    # on a nixpkgs bump that changes only the vendoring code.  rustc (1.89.0)
    # and gcc (14.3.0) both apply the *last* matching map, so the general one
    # stays first.
    export CARGO_TARGET_${rustTargetEnv}_RUSTFLAGS="--remap-path-prefix=$NIX_BUILD_TOP=/home/clightning ${vendorRemap} -C link-arg=-Wl,--build-id=sha1"

    # The static link, stated here and not in configure.
    #
    # pkgsStatic's stdenv adapter appends `-static` to NIX_CFLAGS_LINK, and
    # `-static` wins the crt selection in gcc's spec: a -static-pie link
    # then picks crtbeginT.o/crt1.o (the non-PIE pair) and dies with
    #   "relocation R_X86_64_32 against hidden symbol `__TMC_END__'
    #    can not be used when making a PIE object".
    #
    # NIX_CFLAGS_LINK is NOT the place to correct that: it is unsalted, so
    # the cross cc and the *build-platform* cc both read it.  Putting
    # -static-pie there links cargo's build scripts and proc macros --
    # ordinary glibc host binaries -- as static-pie glibc, which builds and
    # then dies at run time with SIGSEGV.  So: drop `-static` here, and put
    # the static-pie link on the target compiler alone.
    export NIX_CFLAGS_LINK="''${NIX_CFLAGS_LINK//-static/}"

    # nixpkgs' toolchain emits no build-id at all (Alpine's gcc specs did,
    # so this never had to be asked before).  The release keeps the
    # build-id: it is what makes a stripped crash report resolvable, and it
    # carries no function names.  sha1 is over the contents, so it stays
    # deterministic across runs.  It has to be asked for on both link
    # paths -- CC below for C, rustflags above for the Rust plugins.

    # PostgreSQL, statically linked in (static
    # libpq the thing that set the nixpkgs floor).  There is no `pg_config`
    # on PATH here -- and on a cross row there could not be a *runnable*
    # one -- so these exports are the only thing that tells configure how
    # to reach libpq.  Two ways this silently produced a lightningd with no
    # PostgreSQL support at all, both fixed:
    #
    #   * `configure`'s no-pg_config branch *assigned* these two variables
    #     empty instead of defaulting them, discarding the environment
    #     (fixed in `configure` itself);
    #   * the archive names are the Alpine ones.  Alpine's libpq.a needs
    #     `-lpgcommon_shlib -lpgport_shlib`; nixpkgs builds
    #     libpq static-only and ships plain `libpgcommon.a`/`libpgport.a`,
    #     so the `_shlib` names resolve to nothing, the probe fails to
    #     link, and HAVE_POSTGRES comes out 0 with only a
    #     `checking for postgres... no` in the log to show for it.
    #
    # The `-L` is not optional either: nixpkgs' static libpq puts its
    # archives in the **dev** output's `lib/` and leaves `out` holding a
    # single empty marker file, so the cc wrapper's automatic `-L$out/lib`
    # points at nothing.  Link order and library set are nixpkgs' own
    # (libpq's recorded `LIBS`), not pkg-config's `--static` guess, which
    # gets the order wrong.
    export POSTGRES_INCLUDE="-I${lib.getDev libpqRow}/include"
    export POSTGRES_LDLIBS="-L${lib.getDev libpqRow}/lib -L${lib.getLib openssl}/lib -lpq -lpgcommon -lpgport -lssl -lcrypto -lz -lm"
    configureFlagsArray+=( "CC=${releaseCc} -Wl,--build-id=sha1 -ffile-prefix-map=$NIX_BUILD_TOP=/home/clightning" )
  ''
  + lib.optionalString (release && crossRow) ''
    # The configurator itself is a build-machine program (it drives the
    # compiler); its test programs are compiled with CC for the target and
    # *run* through the wrapper.  On the native static row CONFIGURATOR_CC
    # is deliberately left as the musl compiler -- its output runs natively,
    # and changing it would move that row's config.vars.
    export CONFIGURATOR_CC=cc
    export CONFIGURATOR_WRAPPER="${emulator}"
  '';

  enableParallelBuilding = true;

  # The release asks make for `install` and nothing else.
  # nixpkgs' default buildPhase would run the *default* target first, which
  # pulls in ~100 test/fuzz/example programs that never ship -- measured at
  # 18.5 min of pure waste on amd64, and more than the shipped build itself
  # on a cross row.  `install`'s own prerequisite graph already covers
  # everything in the tarball (gen, msggen, the Rust plugins, docs).
  dontBuild = release;

  # Nothing in a fully static tree needs patchelf, and fixupPhase runs it
  # *after* the strip above -- an uncontrolled rewrite of the exact bytes
  # the manifest signs.  The standing guard ("a change made for
  # distribution reasons can move release bytes") applies to nixpkgs' own
  # phases too, so the release opts out rather than trusting it to be a
  # no-op.
  dontPatchELF = release;

  # workaround for build issue, happens only x86_64-darwin, not aarch64-darwin
  # ccan/ccan/fdpass/fdpass.c:16:8: error: variable length array folded to constant array as an extension [-Werror,-Wgnu-folding-constant]
  #                 char buf[CMSG_SPACE(sizeof(fd))];
  env = {
    NIX_CFLAGS_COMPILE = lib.optionalString (
      stdenv.isDarwin && stdenv.isx86_64
    ) "-Wno-error=gnu-folding-constant";
  }

  # Pin gcc's random seed.  nixpkgs' `reproducible-builds.sh`
  # setup hook passes `-frandom-seed=<first 10 chars of $out's name>` to every
  # C compilation, gcc records its switches in DW_AT_producer, and
  # `--build-id=sha1` hashes the *unstripped* output -- so every shipped C
  # binary's build-id was a function of the output store path, which moves
  # when any tracked file moves, compiled or not.  The `--strip-all` below then
  # deletes the evidence and keeps the consequence.  The hook reads
  # NIX_OUTPATH_USED_AS_RANDOM_SEED first; one constant for this package is
  # what the hook's own comment contemplates.
  // lib.optionalAttrs release releaseEnv;

  # Release installs into a DESTDIR with --prefix=/usr/local, so the tarball
  # unpacks over `/` and lands where CLN has always documented it.  The DESTDIR is in
  # the build directory, not $out: $out holds only the tarball.
  preInstall = lib.optionalString release ''
    dest=$NIX_BUILD_TOP/dest
    installFlagsArray+=("DESTDIR=$dest")
  '';

  # Every shipped ELF is stripped, and the result is asserted rather than
  # assumed.  It keeps the tarballs small and matches what every other release
  # of this project shipped; the build-id survives, so a crash in a stripped
  # binary is still resolvable against the unstripped twin kept beside it.
  #
  # nixpkgs' own fixupPhase is not enough on its own: it runs
  # `--strip-debug` over bin/ and lib/, keeping .symtab, and its behaviour
  # across cross/static stdenvs is not something the release should depend
  # on.  So: strip everything explicitly with --strip-all, then *assert* the
  # result over the whole tree.  If the assertion ever fails the build
  # fails; nothing unstripped can reach a tarball.
  postInstall =
    if release then
      ''
        strip_one() {
          ${stdenv.cc.targetPrefix}strip --strip-all --preserve-dates "$1" \
            || { echo "strip failed on $1" >&2; exit 1; }
        }
        find "$dest" -type f -print0 | while IFS= read -r -d "" fp; do
          case "$(head -c 4 "$fp" | od -An -tx1 | tr -d " \n")" in
            7f454c46) strip_one "$fp" ;;
          esac
        done

        # The assertion.  Every ELF: no .symtab, no .debug_*, and a
        # build-id still present (the build-id is kept so a crash
        # report stays resolvable -- it carries no function names).
        fail=0
        find "$dest" -type f -print0 | while IFS= read -r -d "" fp; do
          case "$(head -c 4 "$fp" | od -An -tx1 | tr -d " \n")" in
            7f454c46) ;;
            *) continue ;;
          esac
          sections=$(${stdenv.cc.targetPrefix}readelf -SW "$fp" 2>/dev/null || true)
          if printf '%s' "$sections" | grep -qE '\.symtab|\.debug_'; then
            echo "STRIP CHECK FAILED: $fp still carries .symtab/.debug_*" >&2
            fail=1
          fi
          if readelf_dyn=$(${stdenv.cc.targetPrefix}readelf -dlW "$fp" 2>/dev/null) \
            && printf '%s' "$readelf_dyn" | grep -qE 'RPATH|RUNPATH|INTERP'; then
            echo "STATIC CHECK FAILED: $fp has an rpath or interpreter" >&2
            fail=1
          fi
          if ! printf '%s' "$sections" | grep -q '\.note\.gnu\.build-id'; then
            echo "STRIP CHECK FAILED: $fp has no build-id" >&2
            fail=1
          fi
          [ "$fail" = 0 ] || exit 1
        done

        # The tarball is this derivation's output, so `nix build
        # --rebuild` covers the bytes that are signed and no host's tar or xz
        # sits inside the promise.  The recipe:
        # the artifact name, sorted entries, fixed mtime, numeric root
        # ownership, and ./usr only.  --mode normalises what `make install`
        # left, so unpacking over `/` never leaves /usr unwritable.  xz is
        # pinned to one thread: since xz 5.4 the default is multi-threaded,
        # whose block layout depends on the machine's core count.
        mkdir -p $out
        tar --sort=name --mtime="${mtime} 00:00Z" \
            --owner=0 --group=0 --numeric-owner --mode='u+rwX,go=rX' \
            -cf - -C "$dest" ./usr \
          | xz -T1 -6 -c > $out/clightning-${version}-static-${releaseArch}.tar.xz
      ''
    else
      ''
        cp ${config.packages.rust}/bin/cln-grpc $out/libexec/c-lightning/plugins
        cp ${config.packages.rust}/bin/clnrest $out/libexec/c-lightning/plugins
      '';

  # What this row's release build is made of, in words a
  # reviewer who does not read Nix can diff.  Only *direct* inputs: anything
  # transitive cannot change without a nixpkgs bump, which the certified-rev
  # guard already catches.  The flake compares it with the committed
  # nix/release-manifests/cln-<arch> and `tools/reprobuild certify` rewrites
  # that file.
  passthru.releaseManifest =
    let
      nv = d: "${lib.getName d} ${lib.getVersion d}";
      section = title: lines: "${title}\n" + lib.concatMapStrings (l: "  ${l}\n") lines;
    in
    lib.optionalString release (
      section "row" [
        "arch ${releaseArch}"
        "host ${stdenv.hostPlatform.config}"
      ]
      # The recipe itself, by content hash.  Everything below describes the
      # build's *inputs* -- which package versions, which flags -- and says
      # nothing about the files that decide what is done with them.  Without
      # this, an edit to static-pie.nix could change how every shipped binary
      # is linked, move the output bytes, and leave this manifest
      # byte-identical, so guard 2 would not fire: the compiler wrapper
      # reaches the build through configureFlagsArray in the build phase and
      # the Rust linker through an exported variable, and neither is in the
      # configureFlags attribute the flags section below is built from.
      + section "recipe" [
        "default.nix ${builtins.hashFile "sha256" ./default.nix}"
        "static-pie.nix ${builtins.hashFile "sha256" ./static-pie.nix}"
        "flake-module.nix ${builtins.hashFile "sha256" ./flake-module.nix}"
      ]
      + section "toolchain" [
        "gcc ${stdenv.cc.cc.version}"
        "rustc ${bp.rustc.version}"
        "python ${bp.python3.version}"
      ]
      + section "nativeBuildInputs" (lib.sort lib.lessThan (map nv nativeInputs))
      + section "buildInputs" (lib.sort lib.lessThan (map nv hostInputs))
      + section "flags" (
        [
          "configure ${lib.concatStringsSep " " configureFlags}"
          "dontBuild true"
          "dontPatchELF true"
          "strip --strip-all"
        ]
        ++ [ "rustflags ${rustflagsShape}" ]
        ++ lib.mapAttrsToList (k: v: "env ${k}=${v}") releaseEnv
        ++ map (f: "make ${f}") releaseMakeFlags
      )
    );

  meta = with lib; {
    description = "Core Lightning (CLN): A specification compliant Lightning Network implementation in C";
    homepage = "https://github.com/ElementsProject/lightning";
    license = licenses.mit;
    platforms = platforms.linux ++ platforms.darwin;
  };
}
