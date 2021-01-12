#! /bin/sh
set -e

# When run inside docker (from below), we do build and drop result in /release
if [ x"$1" = x"--inside-docker" ]; then
    VER="$2"
    git clone /src /build
    cd /build
    ./configure
    make
    make install DESTDIR=/"$VER"
    cd /"$VER" && tar cvfz /release/clightning-"$VER".tar.gz -- *
    exit 0
fi

# bin-Ubuntu-16.04-amd64 was superceded by the reproducible built 18.04 version.
ALL_TARGETS="bin-Fedora-28-amd64 zipfile"

FORCE_VERSION=
FORCE_UNCLEAN=false

for arg; do
    case "$arg" in
	--force-mtime=*)
	    FORCE_MTIME=${arg#*=}
	    ;;
	--force-version=*)
	    FORCE_VERSION=${arg#*=}
	    ;;
	--force-unclean)
	    FORCE_UNCLEAN=true
	    ;;
	--help)
	    echo "Usage: [--force-version=<ver>] [--force-unclean]  [--force-mtime=YYYY-MM-DD] [TARGETS]"
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

# `status --porcelain -u no` suppressed modified!  Bug reported...
if [ "$(git diff --name-only)" != "" ] && ! $FORCE_UNCLEAN; then
    echo "Not a clean git directory" >&2
    exit 1
fi

VERSION=$(git tag --points-at HEAD)
VERSION=${VERSION:-$FORCE_VERSION}
if [ "$VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

# Skip 'v' here in $VERSION
MTIME=${FORCE_MTIME:-$(sed -n "s/^## \\[.*${VERSION#v}\\] - \\([-0-9]*\\).*/\\1/p" < CHANGELOG.md)}
if [ -z "$MTIME" ]; then
    echo "No date found for $VERSION in CHANGELOG.md" >&2
    exit 1
fi

# If it's a completely clean directory, we need submodules!
make submodcheck

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
	*)
	    echo "No Dockerfile for $platform" >&2
	    exit 1
    esac

    docker build -f $DOCKERFILE -t $TAG .
    docker run --rm=true -v "$(pwd)":/src:ro -v "$(pwd)"/release:/release $TAG /src/tools/build-release.sh --inside-docker "$VERSION-$platform"
    docker run --rm=true -w /build $TAG rm -rf /"$VERSION-$platform" /build
done

if [ -z "${TARGETS##* zipfile *}" ]; then
    mkdir "release/clightning-$VERSION"
    # git archive won't go into submodules :(; We use tar to copy
    git ls-files -z --recurse-submodules | tar --null --files-from=- -c -f - | (cd "release/clightning-$VERSION" && tar xf -)
    # tar can set dates on files, but zip cares about dates in directories!
    # We set to local time (not "$MTIME 00:00Z") because zip uses local time!
    find "release/clightning-$VERSION" -print0 | xargs -0r touch --no-dereference --date="$MTIME"
    # Seriously, we can have differing permissions, too.  Normalize.
    # Directories become drwxr-xr-x
    find "release/clightning-$VERSION" -type d -print0 | xargs -0r chmod 755
    # Executables become -rwxr-xr-x
    find "release/clightning-$VERSION" -type f -perm -100 -print0 | xargs -0r chmod 755
    # Non-executables become -rw-r--r--
    find "release/clightning-$VERSION" -type f ! -perm -100 -print0 | xargs -0r chmod 644
    # zip -r doesn't have a deterministic order, and git ls-files does.
    LANG=C git ls-files --recurse-submodules | sed "s@^@clightning-$VERSION/@" | (cd release && zip -@ -X "clightning-$VERSION.zip")
    rm -r "release/clightning-$VERSION"
fi

if [ -z "${TARGETS##* sign *}" ]; then
    sha256sum release/clightning-"$VERSION"* > release/SHA256SUMS
    gpg -sb --armor -o release/SHA256SUMS.asc-"$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')" release/SHA256SUMS
fi
