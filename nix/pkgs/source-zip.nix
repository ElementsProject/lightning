# the source zip, as a derivation.
#
# The tarball is a Nix output so `nix build --rebuild` covers the
# bytes that are signed.  The zip is signed too, and it was the last artifact
# still assembled on the host -- out of `git ls-files --recurse-submodules` of
# the *working tree*, which is not the rev the manifest names.  A co-signer
# standing on a different commit therefore rebuilt a different zip and looked
# like a reproducibility failure (caught by `verify` on 2026-09-23).
#
# Built from the flake source, so its content is exactly the tree at that rev
# with its submodules, and nothing on the host (zip version, locale, umask)
# sits inside the signed bytes.
{
  lib,
  stdenvNoCC,
  zip,
  releaseVersion,
  releaseMtime,
}:
stdenvNoCC.mkDerivation {
  pname = "clightning-source-zip";
  version = releaseVersion;
  src = ../../.;

  nativeBuildInputs = [ zip ];

  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;

  # Same rename as the tarball derivation: the unpacked directory
  # is named after the source store path, and that name would otherwise be the
  # top-level directory inside the zip.
  postUnpack = ''
    mv -- "$sourceRoot" source
    export sourceRoot=source
  '';

  installPhase = ''
    runHook preInstall

    dir=clightning-${releaseVersion}
    mkdir -p "$NIX_BUILD_TOP/stage/$dir"
    cp -a . "$NIX_BUILD_TOP/stage/$dir/"
    cd "$NIX_BUILD_TOP/stage"

    # zip records a date on directories as well as files, and reads it in
    # *local* time -- TZ is fixed here so the recorded stamps do not follow
    # the builder's zone.  Modes are normalised for the same reason the
    # tarball normalises them: the store is read-only, and a release should
    # not hand anyone a tree they cannot write to.
    export TZ=UTC
    find "$dir" -print0 | xargs -0r touch --no-dereference --date="${releaseMtime}"
    find "$dir" -type d -print0 | xargs -0r chmod 755
    find "$dir" -type f -perm -100 -print0 | xargs -0r chmod 755
    find "$dir" -type f ! -perm -100 -print0 | xargs -0r chmod 644

    # -X drops uid/gid and extra timestamp fields; the entry order is fixed by
    # feeding a sorted list rather than letting `zip -r` walk the tree, which
    # has no defined order.
    find "$dir" | LC_ALL=C sort > "$NIX_BUILD_TOP/filelist"
    mkdir -p $out
    zip -q -X -@ "$out/clightning-${releaseVersion}.zip" < "$NIX_BUILD_TOP/filelist"

    runHook postInstall
  '';

  meta = with lib; {
    description = "Core Lightning source zip for a release";
    license = licenses.mit;
  };
}
