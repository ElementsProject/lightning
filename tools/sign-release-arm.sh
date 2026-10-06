#! /bin/sh
# Checksum and sign the release tarballs of one ARM architecture.
#
# build-release.sh's sign target cannot be used for these: it hardcodes
# `cd release/` rather than honouring RELEASEDIR, and globs the zip, so
# running it for an ARM build would rewrite the amd64 manifest instead.
#
# Each architecture gets its own manifest, SHA256SUMS-<version>-<arch>:
# arm64 builds natively and armv7 is cross-compiled, so they are reproduced
# (and co-signed) separately.
#
# Usage: tools/sign-release-arm.sh v26.06.9 arm64|armv7 [gpg-key-id]
set -e

VERSION=${1:-}
ARCH=${2:-}
KEY=${3:-}
case "$ARCH" in
    arm64|armv7) ;;
    *)
        echo "Usage: $0 <version> arm64|armv7 [gpg-key-id]" >&2
        exit 1
        ;;
esac
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> arm64|armv7 [gpg-key-id]" >&2
    exit 1
fi

RELEASEDIR="$(pwd)/release-$ARCH"
SUMS="SHA256SUMS-$VERSION-$ARCH"

[ -d "$RELEASEDIR" ] || { echo "No $RELEASEDIR: build the $ARCH tarballs first" >&2; exit 1; }
cd "$RELEASEDIR"

set -- clightning-"$VERSION"-*-"$ARCH".tar.*
[ -e "$1" ] || { echo "No $ARCH tarballs for $VERSION in $RELEASEDIR" >&2; exit 1; }

# sha256sum is GNU; macOS ships shasum.
if command -v sha256sum >/dev/null; then
    SHA256SUM="sha256sum"
else
    SHA256SUM="shasum -a 256"
fi

echo "Checksumming $# $ARCH tarball(s) into $SUMS"
$SHA256SUM "$@" > "$SUMS"
cat "$SUMS"

if [ -z "$KEY" ]; then
    KEY=$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')
fi
[ -n "$KEY" ] || { echo "No signing key: pass one, or set default-key in gpg.conf" >&2; exit 1; }

echo "Signing $SUMS with $KEY"
gpg -sb --armor --default-key "$KEY" -o "$SUMS.asc" "$SUMS"
gpg --verify "$SUMS.asc" "$SUMS"
echo "Signed: $RELEASEDIR/$SUMS.asc"

# Aggregating other people's signatures
#
# Concatenating .asc files can silently produce a file gpg only half-reads:
# an armor block whose BEGIN line is not followed by a blank line yields
# "invalid armor header" and a CRC error, and gpg then verifies only the
# blocks it managed to parse. Normalise before appending:
#
#   awk '/^-----BEGIN PGP SIGNATURE-----$/{print; getline l; if (l != "") print ""; print l; next} {print}' \
#       theirs.asc >> SHA256SUMS-<version>-<arch>.asc
#
# Then confirm the count is what you expect:
#   gpg --verify SHA256SUMS-<version>-<arch>.asc SHA256SUMS-<version>-<arch> 2>&1 | grep -c "Good signature"
