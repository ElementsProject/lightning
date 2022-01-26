#! /bin/sh
set -e

# When run inside docker (from below), we do build and drop result in /release
if [ "$1" = "--inside-docker" ]; then
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
ALL_TARGETS="bin-Fedora-28-amd64 zipfile tarball deb"

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

RELEASEDIR="$(pwd)/release"
BARE_VERSION="$(echo "${VERSION}" | sed 's/^v//g')"
TARBALL="${RELEASEDIR}/lightningd_${BARE_VERSION}.orig.tar.bz2"
DATE=$(date +%Y%m%d%H%M%S)


if [ -z "${TARGETS##* tarball *}" ]; then
    TMPDIR="$(mktemp -d /tmp/lightningd-tarball.XXXXXX)"
    DIR="${TMPDIR}/lightningd_${BARE_VERSION}"
    DESTINATION="${RELEASEDIR}/lightningd_${BARE_VERSION}.orig.tar.bz2"
    echo "Bundling tarball in ${DIR}"
    git clone --recursive . "${DIR}"
    (
	cd "${DIR}"
	# Materialize the version in the Makefile, allows us to skip
	# the git dependency
	sed -i "/^VERSION=/c\VERSION=v${BARE_VERSION}" "Makefile"
	./configure --disable-valgrind --enable-developer --enable-experimental-features
	make doc-all check-gen-updated clean
	find . -name .git -type d -print0 | xargs -0 /bin/rm -rf
    )

    (
	cd "$TMPDIR"
	tar -cjvf "${DESTINATION}" "lightningd_${BARE_VERSION}"
    )

    rm -rf "${TMPDIR}"
fi

if [ -z "${TARGETS##* deb *}" ]; then
    TMPDIR="$(mktemp -d /tmp/lightningd-deb.XXXXXX)"
    SRCDIR="$(pwd)"
    BLDDIR="${TMPDIR}/clightning-${VERSION}"
    ARCH="$(dpkg-architecture -q DEB_BUILD_ARCH)"

    for SUITE in bionic focal hirsute xenial hirsute impish; do

	mkdir -p "${BLDDIR}"
	echo "Building ${BARE_VERSION} in ${TMPDIR}"

	# Stage the source directory, with the debian directory bolted on
	# until we add it to contrib
	tar --directory="$BLDDIR" --strip-components=1 -xjf "${TARBALL}"
	cp -R "${SRCDIR}/debian" "${BLDDIR}"

	# Stage the tarball so `debuild` can find it in the parent of the
	# source directory.
	cp "${TARBALL}" "${TMPDIR}"
	cp "${TARBALL}" "${TMPDIR}/lightningd_${BARE_VERSION}~${DATE}~${SUITE}.orig.tar.bz2"

	# Now actually build all the artifacts.
	#(cd "${BLDDIR}" && debuild -i -us -uc -b)
	(
	    cd "${BLDDIR}"
	    # Add a dummy changelog entry
	    dch -D "${SUITE}" -v "${BARE_VERSION}~${DATE}~${SUITE}" "Upstream release $BARE_VERSION"
	    head debian/changelog
	    debuild -k5B7EE09E54473A764A23515B25B5BC531246001A -S
	    debuild -k5B7EE09E54473A764A23515B25B5BC531246001A -b
	)
	rm -rf "${BLDDIR}"

	# Save the debs locally
	cp -v "${TMPDIR}/lightningd_${BARE_VERSION}~${DATE}~${SUITE}_${ARCH}.deb" "${RELEASEDIR}"
	cp -v "${TMPDIR}/lightningd-dbgsym_${BARE_VERSION}~${DATE}~${SUITE}_${ARCH}.ddeb" "${RELEASEDIR}"

	# Send to PPA
	dput ppa:cdecker/clightning "${TMPDIR}/lightningd_${BARE_VERSION}~${DATE}~${SUITE}_source.changes"
    done
    rm -rf "${TMPDIR}"
fi

if [ -z "${TARGETS##* docker *}" ]; then
    TMPDIR="$(mktemp -d /tmp/lightningd-docker.XXXXXX)"
    SRCDIR="$(pwd)"
    echo "Bundling tarball in ${TMPDIR}"
    git clone --recursive . "${TMPDIR}"
    (
	cd "${TMPDIR}"
	git checkout "v${BARE_VERSION}"
	cp "${SRCDIR}/Dockerfile" "${TMPDIR}/"
	sudo docker build -t elementsproject/lightningd:latest .
	sudo docker tag "elementsproject/lightningd:latest" "elementsproject/lightningd:v${BARE_VERSION}"
    )
    rm -rf "${TMPDIR}"
fi

if [ -z "${TARGETS##* sign *}" ]; then
    sha256sum release/clightning-"$VERSION"* > release/SHA256SUMS
    gpg -sb --armor -o release/SHA256SUMS.asc-"$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')" release/SHA256SUMS
fi
