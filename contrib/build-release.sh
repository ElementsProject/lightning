#! /bin/sh
set -e

if [ "$(git status --porcelain -u no)" != "" ]; then
    echo "Not a clean git directory" >&2
    exit 1
fi

VERSION=`git tag --points-at HEAD`
if [ "$VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

# Make sure repo is clean.
make distclean

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
    docker run --rm=true -v `pwd`:/build -w /build $TAG ./configure
    docker run --rm=true -v `pwd`:/build -w /build $TAG make -j3
    docker run --rm=true -v `pwd`:/build -w /build $TAG make install DESTDIR=/build/$VERSION-$platform
    (cd $VERSION-$platform && tar cvfz ../clightning-$VERSION-$platform.tar.gz *)
    docker run --rm=true -v `pwd`:/build -w /build $TAG rm -rf $VERSION-$platform
    docker run --rm=true -v `pwd`:/build -w /build $TAG make distclean
done

git archive --format=zip -o clightning-$VERSION.zip --prefix=lightning-master/ master

sha256sum clightning-$VERSION* > SHA256SUMS
gpg -sb --armor -o SHA256SUMS.asc-$(gpgconf --list-options gpg | awk -F: '$1 == "default-key" {print $10}' | tr -d '"') SHA256SUMS
