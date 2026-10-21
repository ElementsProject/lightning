# VLS's `remote_hsmd_socket`, one static
# binary per release row.
#
# built this as a `vls` *pseudo-distro*: hooks only
# (`contrib/reprobuild/vls/build.sh` + `pins`), no image of its own,
# borrowing the Alpine static builder's sysroot, its `<triple>-clang`
# wrappers and its pinned protoc.  The Nix switch removed the thing it
# borrowed.
#
# What replaces it: a derivation generated over the same
# rows as CLN, so `nix build --rebuild` covers the bytes that are *signed*,
# the strip is asserted in-derivation, and the per-arch cargo
# target comes from the package set rather than a hand-written `arches` row.
#
# The one thing that makes this different from a fourth row of CLN: VLS is a
# **third-party repository at a pinned commit**, so it has its own source and
# its own crate closure.  Both are fixed-output derivations -- the network
# rule is satisfied the same way 35 satisfied it for cargo, by
# hashing before the build rather than trusting the build not to fetch.
{
  lib,
  pkgs,
  # the row's arch token from nix/release-rows; names the artifact.
  releaseArch,
  # which binary of the VLS workspace to build.
  #
  # `remote_hsmd_socket` is the released artifact.  `vlsd` is
  # the **signer daemon it talks to**, and it is built only so the release can
  # be *tested*: `remote_hsmd_socket` is CLN's hsmd replacement and does
  # nothing on its own but listen on port 7701 for vlsd to connect, so the
  # regtest smoke test -- which 46 runs every release -- has no signer without
  # it.  A test binary is never installed under a release name, never listed
  # in a manifest and never signed; it shares this file (and so the pin, the
  # vendor dir and the toolchain) precisely so the thing under test is built
  # from the same inputs as the thing shipped.
  # NB the `vls` prefix: `callPackage` supplies any argument whose name exists
  # in nixpkgs, and nixpkgs has a package called `binary` (`binary-5.3`), so a
  # plain `binary ? "remote_hsmd_socket"` default was silently replaced by that
  # derivation -- surfacing as an unsupported gobject-introspection four levels
  # into GTK, while building the *released* signer.  (`cargoPackage` is free
  # today; it is prefixed anyway, because the next name might not be.)
  vlsBinary ? "remote_hsmd_socket",
  vlsCargoPackage ? "vls-proxy",
}:
let
  inherit (pkgs) stdenv;
  bp = pkgs.buildPackages;
  inherit (import ./static-pie.nix { inherit pkgs lib; }) rustStaticPieCc noRpathEnv extraObjsManifest;
  rustBin = import ./rust-bin.nix { inherit pkgs lib; };

  # --- the pin -------------
  #
  # Which VLS version ships is a release decision with its own review
  # cadence, not a toolchain refresh: in-tree, the rev can only change by
  # someone editing this block, and `nix flake update` cannot move it.
  #
  # `rev` is the *peeled* v0.14.0 tag (the annotated tag is unsigned --
  # research 14 -- so the commit is the pin, not the tag), and it is the same
  # commit built.  `vendorHash` is the crate closure: the human
  # chose a single fixed-output vendor derivation over an in-tree copy of
  # VLS's Cargo.lock on 2026-09-13.  Both hashes belong in 's input
  # manifest, `vendorHash` especially -- it is the one release input here
  # that nixpkgs' own vendoring code can move without any change of ours.
  pin = {
    url = "https://gitlab.com/lightning-signer/validating-lightning-signer.git";
    version = "v0.14.0";
    rev = "9c0fd05c946d549f643d3e1833d8663168d2b0db";
    hash = "sha256-gKTkOOaj7EGunJF/xi7lW5dNNRvzWoj0nKuEIv3+TUk=";
    vendorHash = "sha256-fxPAZV2uSqN4RlWqTZLDHwsl0/RZdhPcg1fhmiNtgQo=";
  };

  src = bp.fetchgit {
    inherit (pin) url rev hash;
  };

  # --- what the binary says it is --------------------------------------
  #
  # `vls-util/build.rs` runs `git describe` and bakes the answer into
  # `GIT_DESC`, which is what `remote_hsmd_socket --version` prints and what
  # goes out as the OTLP service version.  The Alpine hook did a real `git
  # clone`, so it got a real string; a fixed-output source fetch has no
  # `.git`, and the build.rs falls back to the literal `git-desc-failed` --
  # deterministic, so reproducibility is unaffected, but every VLS we ever
  # ship would refuse to say which one it is.
  #
  # So: answer the one question build.rs asks, from the pin itself.  Not a
  # patch to third-party source, and nothing else in the built set shells out
  # to git (only vls-util does; vls-signer-stm32 is excluded from the
  # workspace).  `-0-g` is the `--long` form for a commit that *is* the tag.
  gitDesc = "${pin.version}-0-g${builtins.substring 0 12 pin.rev}";
  gitShim = bp.writeShellScriptBin "git" ''
    if [ "''${1:-}" = describe ]; then
      echo "${gitDesc}"
      exit 0
    fi
    echo "vls: unexpected git invocation: $*" >&2
    exit 1
  '';

  rustTarget = stdenv.hostPlatform.rust.rustcTarget;
  rustTargetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] rustTarget);
  rustTargetVar = builtins.replaceStrings [ "-" ] [ "_" ] rustTarget;

  # the crates.io 403, one layer
  # over.  `fetchCargoVendor` does not fetch crates with `fetchurl` at all,
  # so the User-Agent overlay does not reach it: it runs a python
  # `requests` script (`fetch-cargo-vendor-util`) that sets no UA at all, and
  # crates.io refuses `python-requests/<v>` exactly as it refuses
  # `curl/<v>`.  Every crate 404s -- 403s -- before the build starts.
  #
  # The script is a `let` binding inside nixpkgs' fetch-cargo-vendor.nix, so
  # there is nothing to `.override`; the only seam is the `writers` call that
  # builds it.  Doing that as a *flake overlay* was the first attempt and is
  # a trap worth recording: `fetchCargoVendor`'s outer derivation is an
  # ordinary runCommand that depends on the script, so patching `writers`
  # globally moves the derivation of every nixpkgs package that vendors
  # crates -- including the release toolchain (`x86_64-unknown-linux-musl-
  # cargo` went from 35rali2m... to x3yxsnpd...).  That is a
  # distribution-motivated change silently moving CLN's release bytes, which
  # is the exact failure class 's guards exist to catch.
  #
  # So the patch is scoped to *this* call: our own instance of nixpkgs'
  # fetcher, with a patched `writers` passed in.  Nothing outside VLS sees
  # it, and the vendor dir is fixed-output anyway, so the release bytes are
  # pinned by `vendorHash` either way.
  #
  # Both seams -- the internal file path and the exact line replaced -- can
  # move when the certified nixpkgs rev moves, and `replaceStrings` fails
  # silently: it changes nothing, and the fetch then 403s far from here.
  # So a replacement that did not happen is an evaluation error.
  uaNeedle = "    session = requests.Session()\n";
  fetchCargoVendor = bp.callPackage "${pkgs.path}/pkgs/build-support/rust/fetch-cargo-vendor.nix" {
    writers = bp.writers // {
      writePython3Bin =
        name: args: text:
        bp.writers.writePython3Bin name args (
          if name == "fetch-cargo-vendor-util" then
            assert lib.assertMsg (lib.hasInfix uaNeedle text) ''
              nix/pkgs/vls.nix: nixpkgs' fetch-cargo-vendor-util no longer contains
              the line the User-Agent patch replaces; crates.io would 403 the fetch.
              Re-check the patch against the certified nixpkgs rev.
            '';
            builtins.replaceStrings
              [ uaNeedle ]
              [
                "${uaNeedle}    session.headers.update({\"User-Agent\": \"Nixpkgs fetch-cargo-vendor (Core Lightning reprobuild)\"})\n"
              ]
              text
          else
            text
        );
    };
  };

  # The crate closure, as one fixed-output derivation (the human's choice on
  # 2026-09-13 over an in-tree copy of VLS's Cargo.lock).  It emits a
  # `.cargo/config.toml` with a `@vendor@` placeholder, which is all cargo
  # needs to be fully offline -- the network rule again: hashed
  # before the build, not fetched during it.
  cargoVendor = fetchCargoVendor {
    inherit src;
    hash = pin.vendorHash;
  };
in
stdenv.mkDerivation {
  pname = if vlsBinary == "remote_hsmd_socket" then "vls" else "vls-${vlsBinary}";
  version = lib.removePrefix "v" pin.version;
  inherit src;

  # NOT `rustPlatform.buildRustPackage`, which is the obvious way to write
  # this and the wrong one.  Its `rustPlatform` resolves to the *row's* rust
  # toolchain, so the amd64 row started compiling an
  # `x86_64-unknown-linux-musl-rustc` and cargo from rustc-1.89.0-src -- a
  # toolchain built here, inside the inputs of a signed artifact, where CLN
  # gets a substituted one (measured exactly this asymmetry between
  # the native and cross rows).  CLN's release path instead uses the
  # *build-platform* cargo/rustc and names the target with
  # CARGO_BUILD_TARGET; VLS does the same, so both released binaries come
  # out of one toolchain.  buildRustPackage's hooks are no loss: its
  # cargo-auditable default embeds a `.dep-v0` SBOM section that
  # `strip --strip-all` deletes again, and its install hook would copy
  # every binary in the workspace.
  nativeBuildInputs = [
    rustBin
    # `vlsd` and `lightning-storage-server` drive prost/tonic codegen.
    bp.protobuf
    gitShim
    # Same class as CC_FOR_BUILD in CLN's own derivation: cargo
    # compiles build scripts and proc macros *for the build machine* and asks
    # rustc for its default linker, which is plain `cc`.  A cross (or
    # pkgsStatic) stdenv only puts `<triple>-gcc` on PATH.
    bp.stdenv.cc
  ];

  dontConfigure = true;
  enableParallelBuilding = true;

  buildPhase = ''
    runHook preBuild

    export SOURCE_DATE_EPOCH LANG=C LC_ALL=C TZ=UTC
    export PROTOC=${bp.protobuf}/bin/protoc
    export PROTOC_INCLUDE=${bp.protobuf}/include

    # Offline cargo, against the vendored crates.
    export CARGO_HOME=$NIX_BUILD_TOP/cargo-home
    mkdir -p $CARGO_HOME
    sed "s|@vendor@|${cargoVendor}|g" ${cargoVendor}/.cargo/config.toml > $CARGO_HOME/config.toml

    export CARGO_BUILD_TARGET=${rustTarget}

    # the wrapper: rustc still links a crt-static musl target
    # non-PIE *and* self-contained at 1.89.0, so the link line is rewritten
    # (crt1.o -> rcrt1.o, crtbegin.o -> crtbeginS.o, `-static` dropped).
    # The release wants static-pie on every shipped ELF, VLS included.
    export CARGO_TARGET_${rustTargetEnv}_LINKER=${rustStaticPieCc}/bin/${stdenv.cc.targetPrefix}rust-cc

    # nixpkgs' toolchain emits no build-id; the release keeps one so a
    # stripped crash report stays resolvable.  The remap is belt and braces
    # here -- unlike CLN's, this source is a fixed-output store path, the
    # same on every machine -- but it also makes the build directory a
    # non-input, which is exactly what watched go wrong.
    # the vendor dir is remapped too, as did for CLN.
    # Without it the binary carries ~500 panic-location strings naming
    # `<hash>-cargo-deps-vendor/...`, so the shipped bytes track a store path
    # that nixpkgs' own vendoring code can move with no change of ours -- the
    # one input 38 singled out as movable from outside.  rustc applies the
    # *last* matching map, so the general one stays first.
    export CARGO_TARGET_${rustTargetEnv}_RUSTFLAGS="--remap-path-prefix=$NIX_BUILD_TOP=/home/clightning --remap-path-prefix=${cargoVendor}=/home/clightning/vendor -C link-arg=-Wl,--build-id=sha1"

    # VLS pulls in C through cc-rs (secp256k1-sys and friends), which reads
    # these rather than the stdenv's exported CC.  The Alpine hook set the
    # same pair by hand against its `arches` row; here the row supplies them.
    export CC_${rustTargetVar}=${stdenv.cc.targetPrefix}cc
    export AR_${rustTargetVar}=${stdenv.cc.targetPrefix}ar

    # the second silent hazard: NIX_CFLAGS_LINK is unsalted, so pkgsStatic's
    # appended `-static` also reaches the *build-platform* cc that compiles
    # cargo's build scripts and proc macros.  The static link belongs on the
    # target compiler alone (it is in the wrapper above).
    export NIX_CFLAGS_LINK="''${NIX_CFLAGS_LINK//-static/}"

    # the rule releases `remote_hsmd_socket` and nothing else; the
    # workspace also holds remote_hsmd_serial, decode-vls, vlsd and vls-cli.
    # Default features (grpc, main, debug), which is what built.
    cargo build --offline --locked --release --jobs "$NIX_BUILD_CORES" \
      -p ${vlsCargoPackage} --bin ${vlsBinary}

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    # /s10: a *released* binary's output is the artifact itself, under
    # its release name (remote_hsmd_socket-<vls-version>-<arch>, ).
    # A test binary goes in bin/ under its own name, so nothing can mistake it
    # for something a manifest should list.
    ${
      if vlsBinary == "remote_hsmd_socket" then
        ''
          install -Dm755 target/${rustTarget}/release/${vlsBinary} \
                $out/${vlsBinary}-${pin.version}-${releaseArch}''
      else
        ''install -Dm755 target/${rustTarget}/release/${vlsBinary} $out/bin/${vlsBinary}''
    }
    runHook postInstall
  '';

  # Nothing static needs patchelf, and fixupPhase runs it *after* the strip
  # below -- an uncontrolled rewrite of the exact bytes the manifest signs.
  dontPatchELF = true;

  # see `noRpathEnv` in static-pie.nix (arm32 only).
  env = noRpathEnv;

  # Stripped, asserted rather than assumed, by the same recipe Core Lightning's
  # derivation uses: the two must ship the same way, and an assertion that fails
  # the build is the only version of this that cannot degrade quietly.
  postInstall = ''
    strip_one() {
      ${stdenv.cc.targetPrefix}strip --strip-all --preserve-dates "$1" \
        || { echo "strip failed on $1" >&2; exit 1; }
    }
    find $out -type f -print0 | while IFS= read -r -d "" fp; do
      case "$(head -c 4 "$fp" | od -An -tx1 | tr -d " \n")" in
        7f454c46) strip_one "$fp" ;;
      esac
    done

    fail=0
    find $out -type f -print0 | while IFS= read -r -d "" fp; do
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
  '';

  #  (, the amendment): the VLS row's input manifest.  The
  # pin is its own identity -- a CLN tree change does not move these bytes --
  # and `vendorHash` is the input nixpkgs' vendoring code can move with no
  # change of ours, so both are spelled out here.
  passthru.releaseManifest =
    let
      section = title: lines: "${title}\n" + lib.concatMapStrings (l: "  ${l}\n") lines;
    in
    section "row" [
      "arch ${releaseArch}"
      "host ${stdenv.hostPlatform.config}"
    ]
    # See the same section in default.nix: the pin below says which VLS, and
    # the flags say how, but neither covers the files that decide the link.
    + section "recipe" [
      "vls.nix ${builtins.hashFile "sha256" ./vls.nix}"
      "static-pie.nix ${builtins.hashFile "sha256" ./static-pie.nix}"
      "flake.nix ${builtins.hashFile "sha256" ../../flake.nix}"
      "rust-bin.nix ${builtins.hashFile "sha256" ./rust-bin.nix}"
    ]
    + section "pin" [
      "url ${pin.url}"
      "version ${pin.version}"
      "rev ${pin.rev}"
      "hash ${pin.hash}"
      "vendorHash ${pin.vendorHash}"
      "git-desc ${gitDesc}"
    ]
    + section "toolchain" (
      [
        "gcc ${stdenv.cc.cc.version}"
        "rustc ${rustBin.version}"
        "protobuf ${bp.protobuf.version}"
      ]
      ++ extraObjsManifest
      ++ rustBin.manifestLines
    )
    + section "flags" (
      [
        "cargo build --offline --locked --release -p vls-proxy --bin remote_hsmd_socket"
        "strip --strip-all"
        "rustflags --remap-path-prefix=$NIX_BUILD_TOP=/home/clightning --remap-path-prefix=<cargo-vendor>=/home/clightning/vendor -C link-arg=-Wl,--build-id=sha1"
      ]
      ++ lib.mapAttrsToList (k: v: "env ${k}=${v}") noRpathEnv
    );

  meta = with lib; {
    description = "VLS remote_hsmd_socket, statically linked for a CLN release";
    homepage = "https://gitlab.com/lightning-signer/validating-lightning-signer";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
