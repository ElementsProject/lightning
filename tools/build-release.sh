#! /bin/sh
set -e

# When run inside docker (from below), we do build and drop result in /release
if [ x"$1" = x"--inside-docker" ]; then
    VER="$2"
    git clone /src /build
    cd /build
    ./configure
    make -j3
    make install DESTDIR=/"$VER"
    tar cvfz /release/clightning-"$VER".tar.gz -- *
    exit 0
fi

ALL_TARGETS="bin-Fedora-28-amd64 bin-Ubuntu-16.04-amd64 bin-Ubuntu-16.04-i386 tarball sign"

FORCE_VERSION=
FORCE_UNCLEAN=false

for arg; do
    case "$arg" in
	--force-version=*)
	    FORCE_VERSION=${arg#*=}
	    ;;
	--force-unclean)
	    FORCE_UNCLEAN=true
	    ;;
	--help)
	    echo "Usage: [--force-version=<ver>] [--force-unclean] [TARGETS]"
	    echo Known targets: "$ALL_TARGETS"
	    exit 0
	    ;;
	-*)
	    echo "Unknown arg $arg" >&2
	    exit 1
	    ;;
	*)
	    break
	    ;;
    esac
    shift
done

if [ "$#" = 0 ]; then
    TARGETS=" $ALL_TARGETS "
else
    TARGETS=" $* "
fi

if [ "$(git status --porcelain -u no)" != "" ] && ! $FORCE_UNCLEAN; then
    echo "Not a clean git directory" >&2
    exit 1
fi

VERSION=$(git tag --points-at HEAD)
VERSION=${VERSION:-$FORCE_VERSION}
if [ "$VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

rm -rf release
mkdir -p release
for target in $TARGETS; do
    platform=${target#bin-}
    [ "$platform" != "$target" ] || continue
    case $platform in
	Fedora-28-amd64)
	    DOCKERFILE=contrib/Dockerfile.builder.fedora
	    TAG=fedora
	    ;;
	Ubuntu-16.04-amd64)
	    DOCKERFILE=contrib/Dockerfile.builder
	    TAG=ubuntu-amd64
	    ;;
	Ubuntu-16.04-i386)
	    DOCKERFILE=contrib/Dockerfile.builder.i386
	    TAG=ubuntu-i386
	    ;;
	*)
	    echo "No Dockerfile for $platform" >&2
	    exit 1
    esac

    docker build -f $DOCKERFILE -t $TAG .
    docker run --rm=true -v "$(pwd)":/src:ro -v "$(pwd)"/release:/release $TAG /src/tools/build-release.sh --inside-docker "$VERSION-$platform"
    docker run --rm=true -w /build $TAG rm -rf /"$VERSION-$platform" /build
done

if [ -z "${TARGETS##* tarball *}" ]; then
    # git archive won't go into submodules :(
    ln -sf .. "release/clightning-$VERSION"
    FILES=$(git ls-files --recurse-submodules | sed "s,^,clightning-$VERSION/,")
    # shellcheck disable=SC2086
    (cd release && zip "clightning-$VERSION.zip" $FILES)
    rm "release/clightning-$VERSION"
fi

if [ -z "${TARGETS##* sign *}" ]; then
    sha256sum release/clightning-"$VERSION"* > release/SHA256SUMS
    gpg -sb --armor -o release/SHA256SUMS.asc-"$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')" release/SHA256SUMS
fi
