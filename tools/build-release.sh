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

if [ "$(git status --porcelain -u no)" != "" ]; then
    echo "Not a clean git directory" >&2
    exit 1
fi

VERSION=$(git tag --points-at HEAD)
if [ "$VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

mkdir -p release
for platform in Fedora-28-amd64 Ubuntu-16.04-amd64 Ubuntu-16.04-i386; do
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

git archive --format=zip -o release/clightning-"$VERSION".zip --prefix=lightning-master/ master

sha256sum release/clightning-"$VERSION"* > release/SHA256SUMS
gpg -sb --armor -o release/SHA256SUMS.asc-"$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"')" release/SHA256SUMS
