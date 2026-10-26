{ self, inputs, ... }:
{
  perSystem =
    {
      pkgs,
      config,
      lib,
      system,
      ...
    }:
    let
      # the release
      # matrix is data: `nix/release-rows`, read here with no tooling and by
      # tools/reprobuild with `while read`.  Every release attribute below is
      # generated from it; none is written by hand.
      rowsText = builtins.readFile ../release-rows;
      rowLines = lib.filter (l: l != "" && !(lib.hasPrefix "#" l)) (
        map lib.trim (lib.splitString "\n" rowsText)
      );
      fields = l: lib.filter (f: f != "") (lib.splitString " " (lib.replaceStrings [ "\t" ] [ " " ] l));
      rows = map (
        l:
        let
          f = fields l;
        in
        {
          arch = builtins.elemAt f 0;
          pkgsPath = builtins.elemAt f 1;
          platform = builtins.elemAt f 2;
        }
      ) (lib.filter (l: !(lib.hasPrefix "@" l)) rowLines);
      directive =
        name:
        let
          hits = lib.filter (l: lib.hasPrefix "@${name} " l) rowLines;
        in
        assert lib.assertMsg (
          builtins.length hits == 1
        ) "nix/release-rows: expected exactly one @${name} line";
        builtins.elemAt (fields (builtins.head hits)) 1;

      # --- guard 1: the certified nixpkgs rev --------------------
      #
      # A contributor's `nix flake update`, run to fix a dev-shell paper cut,
      # would otherwise move gcc, rustc and openssl under three signed
      # tarballs without a word.  The error names every way out: a guard
      # whose message does not is a guard people delete.
      certifiedRev = directive "nixpkgs";
      lockedRev = inputs.nixpkgs.rev;
      revOk = certifiedRev == lockedRev;
      revMsg = ''
        The release is certified against nixpkgs ${certifiedRev}
        (nix/release-rows), but flake.lock pins ${lockedRev}.

        Release bytes built from an uncertified nixpkgs are refused.  Either:
          * tools/reprobuild certify              re-certify: from-source build + acceptance suite
          * tools/reprobuild certify --no-verify  record the new rev without the suite (visible in review)
          * git checkout flake.lock               put the certified nixpkgs back
      '';

      # --- guard 2: the committed input manifests -----------------
      manifestFile = name: ../release-manifests + "/${name}";
      manifestOk =
        name: drv:
        builtins.pathExists (manifestFile name)
        && builtins.readFile (manifestFile name) == drv.releaseManifest;
      manifestMsg = name: ''
        nix/release-manifests/${name} does not match what the ${name} release
        derivation is made of (or is missing).  A change reached the release
        path; make it visible in review.  Either:
          * tools/reprobuild certify              regenerate the manifests + acceptance suite
          * tools/reprobuild certify --no-verify  regenerate the manifests only
          * revert the change to nix/ that moved it
      '';

      # Package sets a row can name besides nixpkgs' own.  The armv7 tarball
      # is for the Raspberry Pi 2 and later, and every one of those has NEON
      # and VFPv4 with 32 D registers; nixpkgs' armv7l-hf-multiplatform is
      # Debian's VFPv3-D16 without NEON.  The FPU is baked into gcc
      # (--with-fpu), so this is a separate package set, not a flag.
      releaseSets = {
        pkgsCrossRaspberryPi = import inputs.nixpkgs {
          localSystem = system;
          crossSystem = lib.systems.examples.armv7l-hf-multiplatform // {
            gcc = {
              arch = "armv7-a";
              fpu = "neon-vfpv4";
            };
          };
        };
      };

      pkgsFor =
        row:
        lib.attrByPath (lib.splitString "." row.pkgsPath)
          (throw "nix/release-rows: no package set ${row.pkgsPath}")
          (pkgs // releaseSets);

      # Unguarded: what certify reads to regenerate the manifests, and what
      # the guards compare against.
      rawCln =
        row:
        let
          staticPkgs = pkgsFor row;
        in
        staticPkgs.callPackage ./default.nix {
          inherit self config;
          pkgs = staticPkgs;
          postgresSupport = true;
          release = true;
          releaseArch = row.arch;
          # Defaults for a bare `nix build`; the driver always overrides both.
          # `.version` ends in a newline, which readFile keeps.
          releaseVersion = lib.removeSuffix "\n" (builtins.readFile ../../.version);
          releaseMtime =
            let
              d = self.lastModifiedDate;
            in
            "${builtins.substring 0 4 d}-${builtins.substring 4 2 d}-${builtins.substring 6 2 d}";
        };
      # the source zip is a release artifact too, so it is a
      # derivation like the others -- built from the flake source, not from
      # the host's working tree.
      rawZip = pkgs.callPackage ./source-zip.nix {
        releaseVersion = lib.removeSuffix "\n" (builtins.readFile ../../.version);
        releaseMtime =
          let
            d = self.lastModifiedDate;
          in
          "${builtins.substring 0 4 d}-${builtins.substring 4 2 d}-${builtins.substring 6 2 d}";
      };

      rawVls =
        row:
        let
          staticPkgs = pkgsFor row;
        in
        staticPkgs.callPackage ./vls.nix {
          pkgs = staticPkgs;
          releaseArch = row.arch;
        };

      # the signer daemon `remote_hsmd_socket` talks to, built only
      # so the regtest smoke test has something to test against (46 runs it
      # every release).  Never shipped, never signed, never in a manifest --
      # and built from the same pin, vendor dir and toolchain as the artifact,
      # so the pair under test is the pair released.  Native row only: the
      # test runs lightningd and bitcoind on the build machine.
      rawVlsd =
        let
          staticPkgs = pkgs.pkgsStatic;
        in
        staticPkgs.callPackage ./vls.nix {
          pkgs = staticPkgs;
          releaseArch = "amd64";
          vlsBinary = "vlsd";
          vlsCargoPackage = "vlsd";
        };

      # Guarded: the release attributes refuse to evaluate on either guard.
      # Only here -- `nix build .#cln`, the dev shells and the other checks
      # are untouched.
      guard =
        name: drv:
        lib.throwIfNot revOk revMsg (lib.throwIfNot (manifestOk name drv) (manifestMsg name) drv);

      releaseSystem = system == "x86_64-linux";
      perRow = f: lib.listToAttrs (lib.concatMap f rows);
    in
    {
      packages = rec {
        # This package depends on git submodules so use a shell command like 'nix build .?submodules=1'.
        cln = pkgs.callPackage ./default.nix { inherit self pkgs config; };
        cln-postgres = pkgs.callPackage ./default.nix {
          inherit self pkgs config;
          postgresSupport = true;
        };
        rust = pkgs.callPackage ./rust.nix { craneLib = pkgs.craneLib; };
        default = cln;
      }
      // lib.optionalAttrs releaseSystem {
        # The zip carries no per-row input manifest (its only inputs are the
        # source and `zip` itself), but it is still refused on an uncertified
        # nixpkgs, like every other signed artifact.
        cln-release-source-zip = lib.throwIfNot revOk revMsg rawZip;
        vls-test-vlsd = rawVlsd;
      }
      // lib.optionalAttrs releaseSystem (
        perRow (row: [
          (lib.nameValuePair "cln-release-static-${row.arch}" (guard "cln-${row.arch}" (rawCln row)))
          (lib.nameValuePair "vls-release-static-${row.arch}" (guard "vls-${row.arch}" (rawVls row)))
        ])
      );

      # What tools/reprobuild reads without building anything: the certified
      # and locked revs, and the manifests as the derivations would write
      # them (`certify` copies these into nix/release-manifests/).
      legacyPackages.release = lib.optionalAttrs releaseSystem {
        inherit certifiedRev lockedRev;
        manifests = perRow (row: [
          (lib.nameValuePair "cln-${row.arch}" (rawCln row).releaseManifest)
          (lib.nameValuePair "vls-${row.arch}" (rawVls row).releaseManifest)
        ]);
      };

      # The tripwires: evaluation fails in milliseconds, in the commit that
      # moved flake.lock or the release derivation, not on release day.
      checks = lib.optionalAttrs releaseSystem {
        release-nixpkgs-certified = lib.throwIfNot revOk revMsg (
          pkgs.runCommand "release-nixpkgs-certified" { } "touch $out"
        );
        release-manifests = lib.foldl' (
          acc: row:
          lib.throwIfNot (manifestOk "cln-${row.arch}" (rawCln row)) (manifestMsg "cln-${row.arch}") (
            lib.throwIfNot (manifestOk "vls-${row.arch}" (rawVls row)) (manifestMsg "vls-${row.arch}") acc
          )
        ) (pkgs.runCommand "release-manifests" { } "touch $out") rows;
      };
    };
}
