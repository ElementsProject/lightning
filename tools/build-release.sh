#! /bin/sh
set -e

# When run inside docker (from below), we do build and drop result in /release
if [ "$1" = "--inside-docker" ]; then
    echo "Inside docker: starting build"
    VER="$2"
    PLTFM="$3"
    git clone /src /build
    cd /build
    ./configure
    make VERSION="$VER"
    make install DESTDIR=/"$VER-$PLTFM" RUST_PROFILE=release
    cd /"$VER-$PLTFM" && tar cvfz /release/clightning-"$VER-$PLTFM".tar.gz -- *
    echo "Inside docker: build finished"
    exit 0
fi

FORCE_UNCLEAN=false
VERIFY_RELEASE=false

ALL_TARGETS="bin-Fedora-28-amd64 bin-Ubuntu docker sign"
# ALL_TARGETS="bin-Fedora-28-amd64 bin-Ubuntu tarball deb docker sign"

for arg; do
    case "$arg" in
    --force-version=*)
	    FORCE_VERSION=${arg#*=}
        ;;
    --force-unclean)
        FORCE_UNCLEAN=true
        ;;
    --force-mtime=*)
        FORCE_MTIME=${arg#*=}
        ;;
    --verify)
        VERIFY_RELEASE=true
        ;;
    --help)
        echo "Usage: [--force-version=<ver>] [--force-unclean] [--force-mtime=YYYY-MM-DD] [--verify] [TARGETS]"
        echo Known targets: "$ALL_TARGETS"
	    echo "Example: tools/build-release.sh"
	    echo "Example: tools/build-release.sh --force-version=v23.05 --force-unclean --force-mtime=2023-05-01 bin-Ubuntu sign"
	    echo "Example: tools/build-release.sh --verify"
	    echo "Example: tools/build-release.sh --force-version=v23.05 --force-unclean --force-mtime=2023-05-01 --verify"
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

echo "Verify Release: $VERIFY_RELEASE"
echo "Force mTime: $FORCE_MTIME"
echo "Force Unclean: $FORCE_UNCLEAN"

VERSION=$(git tag --points-at HEAD)
echo "Tagged Version: $VERSION"
VERSION=${FORCE_VERSION:-$VERSION}
echo "Version: $VERSION"

if [ "$VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

# `status --porcelain -u no` suppressed modified!  Bug reported...
if [ "$(git diff --name-only)" != "" ] && ! $FORCE_UNCLEAN; then
    echo "Not a clean git directory" >&2
    exit 1
fi

# Skip 'v' here in $VERSION
MTIME=${FORCE_MTIME:-$(sed -n "s/^## \\[.*${VERSION#v}\\] - \\([-0-9]*\\).*/\\1/p" < CHANGELOG.md)}
echo "mTime: $MTIME"

if [ -z "$MTIME" ]; then
    echo "No date found for $VERSION in CHANGELOG.md" >&2
    exit 1
fi

if [ "$VERIFY_RELEASE" = "true" ]; then
    if [ -f "SHA256SUMS-$VERSION.asc" ] && [ -f "SHA256SUMS-$VERSION" ]; then
        ALL_TARGETS="bin-Ubuntu"
    else
        echo "Unable to verify. File SHA256SUMS-$VERSION or SHA256SUMS-$VERSION.asc not found in the root."
		exit 1
    fi
fi

if [ "$#" = 0 ]; then
    TARGETS=" $ALL_TARGETS "
else
    TARGETS=" $* "
fi

RELEASEDIR="$(pwd)/release"
BARE_VERSION="$(echo "${VERSION}" | sed 's/^v//g')"
TARBALL="${RELEASEDIR}/lightningd_${BARE_VERSION}.orig.tar.bz2"
DATE=$(date +%Y%m%d%H%M%S)
echo "Targets: $TARGETS"
echo "Release Directory: $RELEASEDIR"
echo "Tarball File: $TARBALL"
echo "Current Timestamp: $DATE"

# submodcheck needs to know if we have lowdown
./configure --reconfigure
# If it's a completely clean directory, we need submodules!
make submodcheck
mkdir -p "$RELEASEDIR"

echo "Creating Zip File"
# delete zipfile if exists
[ -f "$RELEASEDIR/clightning-$VERSION.zip" ] && rm "$RELEASEDIR/clightning-$VERSION.zip"
mkdir "$RELEASEDIR/clightning-$VERSION"
# git archive won't go into submodules :(; We use tar to copy
git ls-files -z --recurse-submodules | tar --null --files-from=- -c -f - | (cd "$RELEASEDIR/clightning-$VERSION" && tar xf -)
# tar can set dates on files, but zip cares about dates in directories!
# We set to local time (not "$MTIME 00:00Z") because zip uses local time!
find "$RELEASEDIR/clightning-$VERSION" -print0 | xargs -0r touch --no-dereference --date="$MTIME"
# Seriously, we can have differing permissions, too.  Normalize.
# Directories become drwxr-xr-x
find "$RELEASEDIR/clightning-$VERSION" -type d -print0 | xargs -0r chmod 755
# Executables become -rwxr-xr-x
find "$RELEASEDIR/clightning-$VERSION" -type f -perm -100 -print0 | xargs -0r chmod 755
# Non-executables become -rw-r--r--
find "$RELEASEDIR/clightning-$VERSION" -type f ! -perm -100 -print0 | xargs -0r chmod 644
# zip -r doesn't have a deterministic order, and git ls-files does.
LANG=C git ls-files --recurse-submodules | sed "s@^@clightning-$VERSION/@" | (cd release && zip -@ -X "clightning-$VERSION.zip")
rm -r "$RELEASEDIR/clightning-$VERSION"
echo "Zip File Created"

for target in $TARGETS; do
    platform=${target#bin-}
    [ "$platform" != "$target" ] || continue
    case $platform in
    Fedora-28-amd64)
        echo "Building Fedora Image"
        DOCKERFILE=contrib/docker/Dockerfile.builder.fedora
        TAG=fedora
        docker build -f $DOCKERFILE -t $TAG .
        docker run --rm=true -v "$(pwd)":/src:ro -v "$RELEASEDIR":/release $TAG /src/tools/build-release.sh --inside-docker "$VERSION" "$platform"
        docker run --rm=true -w /build $TAG rm -rf /"$VERSION-$platform" /build
        echo "Fedora Image Built"
        ;;
    Ubuntu)
		for d in bionic focal jammy; do
            # Capitalize the first letter of distro
            D=$(echo "$d" | awk '{print toupper(substr($0,1,1))substr($0,2)}')
			echo "Building Ubuntu $D Image"
			docker run --rm -v "$(pwd)":/build -e FORCE_MTIME="$MTIME" -e FORCE_VERSION="$VERSION" -ti cl-repro-"$d"
            echo "Ubuntu $D Image Built"
		done
        ;;
    *)
        echo "No Dockerfile for $platform" >&2
        exit 1
    esac
done

if [ -z "${TARGETS##* tarball *}" ]; then
    echo "Creating Tarball"
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
	./configure --disable-valgrind --enable-developer
	make doc-all check-gen-updated clean
	find . -name .git -type d -print0 | xargs -0 /bin/rm -rf
    )

    (
	cd "$TMPDIR"
	tar -cjvf "${DESTINATION}" "lightningd_${BARE_VERSION}"
    )

    rm -rf "${TMPDIR}"
    echo "Tarball Created"
fi

if [ -z "${TARGETS##* deb *}" ]; then
    echo "Building Debian Image"
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
    echo "Debian Image Built"
fi

if [ -z "${TARGETS##* docker *}" ]; then
    echo "Building Docker Images"
    for d in amd64 arm64v8 arm32v7; do
        TMPDIR="$(mktemp -d /tmp/lightningd-docker-$d.XXXXXX)"
        SRCDIR="$(pwd)"
        echo "Bundling $d image in ${TMPDIR}"
        git clone --recursive . "${TMPDIR}"
        (
        cd "${TMPDIR}"
        git checkout "v${BARE_VERSION}"
        case "$d" in
            "arm32v7")
                cp "${SRCDIR}/contrib/docker/Dockerfile.$d" "${TMPDIR}/"
                docker buildx build --load --platform linux/arm64 -t "elementsproject/lightningd:$VERSION-$d" -f Dockerfile.$d "${TMPDIR}"
                ;;
            "arm64v8")
                cp "${SRCDIR}/contrib/docker/Dockerfile.$d" "${TMPDIR}/"
                docker buildx build --load --platform linux/arm/v7 -t "elementsproject/lightningd:$VERSION-$d" -f Dockerfile.$d "${TMPDIR}"
                ;;
            *)
                cp "${SRCDIR}/Dockerfile" "${TMPDIR}/"
                docker buildx build --load --platform linux/amd64 -t elementsproject/lightningd:latest -f Dockerfile "${TMPDIR}"
                docker tag "elementsproject/lightningd:latest" "elementsproject/lightningd:$VERSION"
                ;;
        esac
        )
        rm -rf "${TMPDIR}"
    done
    echo "Docker Images Built. Ready to upload on Dockerhub."
fi

if [ -z "${TARGETS##* sign *}" ]; then
    echo "Signing Release"
    cd release/
    sha256sum clightning-"$VERSION"* > SHA256SUMS
    gpg -sb --armor -o SHA256SUMS.asc"$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')" SHA256SUMS
    cd ..
    echo "Release Signed"
fi

if [ "$VERIFY_RELEASE" = "true" ]; then
    echo "Verifying Release"
    cd release/
    # Creating fake Fedora tar for SHA256SUMS match
    # It is important for zipfile checksum match
    touch clightning-v23.05-Fedora-28-amd64.tar.gz
    # Creating SHA256SUMS
	sha256sum clightning-"$VERSION"* > SHA256SUMS
	# Replacing Fedora checksums from root file to release/SHA256SUMS
	# because we do not have reproducible builds for Fedora
	replace_fedora_sums=$(head -n 1 "../SHA256SUMS-$VERSION")
	{ echo "$replace_fedora_sums"; tail -n +2 SHA256SUMS; } > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS
	# compare our and release captain's SHA256SUMS contents
	if [ -f "SHA256SUMS" ] && cmp -s "SHA256SUMS" "../SHA256SUMS-$VERSION"; then
        echo "SHA256SUMS are Identical"
    else
        echo "Error: SHA256SUMS do NOT Match"
		exit 1
    fi
	# verify release captain signature
    gpg --verify "../SHA256SUMS-$VERSION.asc"
	# create ASCII-armored detached signature
    gpg -sb --armor < SHA256SUMS > SHA256SUMS.new
    echo "Verified Successfully! Signature Updated in release/SHA256SUMS.new"
fi

echo "Building release script finished!!"
