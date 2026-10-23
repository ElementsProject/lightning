#! /bin/sh
# ARM64 variant of repro-build.sh.
# Identical to that script except the pinned .deb set: same packages at the
# same upstream versions, built for arm64.  Kept separate so the amd64 path
# cannot be affected by arm64 work.

set -e

LANG=C
LC_ALL=C
export LANG LC_ALL

for arg; do
    case "$arg" in
    --force-version=*)
	FORCE_VERSION=${arg#*=}
        ;;
    --force-mtime=*)
	FORCE_MTIME=${arg#*=}
	;;
    --help)
	echo "Usage: [--force-version=<ver>] [--force-mtime=YYYY-MM-DD]"
	exit 0
	;;
    *)
	echo "Unknown arg $arg" >&2
	exit 1
	;;
    esac
    shift
done

# Taken from https://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script
if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    # shellcheck disable=SC1091
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
elif command -v lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    # shellcheck disable=SC1091
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
    VER=$(cat /etc/debian_version)
else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
fi

ARCH=$(dpkg --print-architecture)
PLATFORM="$OS"-"$VER"
VERSION=${FORCE_VERSION:-$(git describe --tags --always --dirty=-modded --abbrev=7 2>/dev/null || pwd | sed -n 's,.*/clightning-\(v[0-9.rc\-]*\)$,\1,p')}
MAKEPAR=${MAKEPAR:-1}

# eg. ## [0.6.3] - 2019-01-09: "The Smallblock Conspiracy"
# Skip 'v' here in $VERSION
MTIME=${FORCE_MTIME:-$(sed -n "s/^## \\[${VERSION#v}\\] - \\([-0-9]*\\).*/\\1/p" < CHANGELOG.md)}
if [ -z "$MTIME" ]; then
    echo "No date found for $VERSION in CHANGELOG.md" >&2
    exit 1
fi

echo "Repro Version: $VERSION"
echo "Repro mTime: $MTIME"
echo "Repro Platform: $PLATFORM"

if grep ^deb /etc/apt/sources.list | grep -- '-\(updates\|security\)'; then
	echo Please disable security and updates in /etc/apt/sources.list >&2
	exit 1
fi

DOWNLOAD='sudo apt -y --no-install-recommends --reinstall -d install'
PKGS='autoconf automake libtool make gcc libsqlite3-dev zlib1g-dev libsodium-dev'
INST='sudo dpkg -i'

case "$PLATFORM" in
    Ubuntu-22.04)
	cat > /tmp/SHASUMS <<EOF
96b528889794c4134015a63c75050f93d8aecdf5e3f2a20993c1433f4c61b80e  /var/cache/apt/archives/autoconf_2.71-2_all.deb
59e3890fc8407bcf8ccc9f709d6513156346d5c942e8c624dc90435e58f6f978  /var/cache/apt/archives/automake_1%3a1.16.5-1.3_all.deb
aa7cf600950715d8ab9c5eaee72700055ce5ccf741c48617ef0e7a9762992b5d  /var/cache/apt/archives/gcc-11-base_11.2.0-19ubuntu1_arm64.deb
529297dd073285f1a62262fc1d1e2cf07bad3c4f589c1b453c7b1ecde2536886  /var/cache/apt/archives/gcc-11_11.2.0-19ubuntu1_arm64.deb
7a192ee1572c98e15c385c96854fa8c0a674577311325fc7520859fbc94f73c8  /var/cache/apt/archives/libc-bin_2.35-0ubuntu3_arm64.deb
2f254d6e843e413d549f407362885171c285f08383bb7e9392da855810ff78fd  /var/cache/apt/archives/libc6-dev_2.35-0ubuntu3_arm64.deb
29ffcb4b1cd5a085805383475c7e30a080ea1b8d098afa1e2f7dc1c0adbd0621  /var/cache/apt/archives/libcc1-0_12-20220319-1ubuntu1_arm64.deb
17805b64d386655edca4aafbf01e6b89bd3b9a35cde7a31da964dd766ad9c5b6  /var/cache/apt/archives/libcrypt-dev_1%3a4.4.27-1_arm64.deb
ce742ecc7426fb2dd0bfc86365a7419a5c7e2aaed9c3faad9e400a1f1f7e89b1  /var/cache/apt/archives/libgcc-11-dev_11.2.0-19ubuntu1_arm64.deb
f29d0820c300904b6ebd694b07e0adbb2447c7d67bec08bdb025b688e6259342  /var/cache/apt/archives/libpq-dev_14.2-1ubuntu1_arm64.deb
c4929ae6572ccd6556202bb54379ef990d2075475eead1db33bb45f38dd27997  /var/cache/apt/archives/libpq5_14.2-1ubuntu1_arm64.deb
142fd1e8549e94c42327bc3d50cc55aae4117629e4c1590721780cffa0a0c465  /var/cache/apt/archives/libsodium-dev_1.0.18-1build2_arm64.deb
41849b3ede4da9e4f0aef3e3afe72060122d661b83e89418a06a93fe4cec92ba  /var/cache/apt/archives/libsodium23_1.0.18-1build2_arm64.deb
40bda907175e64ef86c85fe47effed8e3dae83804b4a7ae272ad4e01b4813438  /var/cache/apt/archives/libsqlite3-0_3.37.2-2_arm64.deb
ba7d636c4c67dd0831eb86ef1ab27aa3eb85f508031b283401aaa35cf447e8d1  /var/cache/apt/archives/libsqlite3-dev_3.37.2-2_arm64.deb
ffbdfcd181d87b92c108cb49ca20e152c0688825b5a1aac9ecbc63391b348aeb  /var/cache/apt/archives/linux-libc-dev_5.15.0-25.25_arm64.deb
f93a5bf8b5443fceebb7bb507124abdd9a41ea281cb4c18504fd62c070110f79  /var/cache/apt/archives/m4_1.4.18-5ubuntu2_arm64.deb
560a5105bbe3bd33a8c55f10006e3707b77311d19e5928e841f5ee84590a80c6  /var/cache/apt/archives/make_4.3-4.1build1_arm64.deb
2293f3feacd87c471468b36b09f58deec22f74a861bf39265884c3b7b353bea3  /var/cache/apt/archives/zlib1g-dev_1%3a1.2.11.dfsg-2ubuntu9_arm64.deb
597820b01a8b019d04c9f9db2cad80d9d0ed93d39770066bd833e362c526b345  /var/cache/apt/archives/zlib1g_1%3a1.2.11.dfsg-2ubuntu9_arm64.deb
EOF
	;;
    Ubuntu-24.04)
	cat > /tmp/SHASUMS <<EOF
cc3f9f7a1e576173fb59c36652c0a67c6426feae752b352404ba92dfcb1b26c9  /var/cache/apt/archives/autoconf_2.71-3_all.deb
11dec7614bba0bd5b7cfad6a9890a4680dac5de6908ae625dd07105679bad67c  /var/cache/apt/archives/gcc_4%3a13.2.0-7ubuntu1_arm64.deb
afc7b1fedc4316d524aba2d7e5a079c3f7e622b88445b8b8bab2243f6a91c2d5  /var/cache/apt/archives/libsodium-dev_1.0.18-1build3_arm64.deb
66abecbe7d7e9abfa6184f2d6fa581e62b67e90660c690128b06a8f2f7e12a8a  /var/cache/apt/archives/libsqlite3-dev_3.45.1-1ubuntu2_arm64.deb
9d1d707179675d38e024bb13613b1d99e0d33fa6c45e5f3bcba19340781781d3  /var/cache/apt/archives/libtool_2.4.7-7build1_all.deb
3bbbf5d426bc68fc232fc4e20f135aaf3eb76a514839acf82eeffa0dce9c81d4  /var/cache/apt/archives/make_4.3-4.1build2_arm64.deb
66aaebb68401a88b4f70a5f48e1a516b611fdcaae15208d8aee677c556d2cf01  /var/cache/apt/archives/zlib1g_1%3a1.3.dfsg-3.1ubuntu2_arm64.deb
EOF
	;;
    Ubuntu-26.04)
    cat > /tmp/SHASUMS <<EOF
9edd0db0fa94580ab013529d6842a8e89b8ed22ab337da5e95cbb43971978815  /var/cache/apt/archives/autoconf_2.72-3.1ubuntu2_all.deb
1a443abf03a5af97f4493405e22eba52fd6935a8b0583ac32fb88b3727563e53  /var/cache/apt/archives/automake_1%3a1.18.1-3build1_all.deb
dde3a5ce12ecee04b40220d80335123f0070bb154f51b75338e08b69588318bb  /var/cache/apt/archives/gcc_4%3a15.2.0-5ubuntu1_arm64.deb
9299e0c7e4857944e397114e65df342d03c96d976061d4b38d481f2769cf83c4  /var/cache/apt/archives/libsodium-dev_1.0.18-2_arm64.deb
2763a999c733ac5a153bd12ad887754a4c3455ec1167aa3437cce6e85731a01a  /var/cache/apt/archives/libsqlite3-dev_3.46.1-9_arm64.deb
5b3146cd9d380e4725fc5b5e54795ae1f72d165d93e68ce29076b69762661fd4  /var/cache/apt/archives/libtool_2.5.4-9_all.deb
f6221e4b7865332ef903bbfb5763c8e2c0aa98ecf2ee78cc73ba59ad6504d077  /var/cache/apt/archives/make_4.4.1-3_arm64.deb
6225185052192b092a309911f2f831d61d945e7ae17b13a63f4a5494319e4ea7  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg+really1.3.1-1ubuntu3_arm64.deb
EOF
	;;
    *)
	echo Unsupported platform "$PLATFORM" >&2
	exit 1
	;;
esac

# Download the packages
# shellcheck disable=SC2086
$DOWNLOAD $PKGS

# Make sure versions match, and exactly.
sha256sum -c /tmp/SHASUMS

# Install them
# shellcheck disable=SC2046
$INST $(cut -c66- < /tmp/SHASUMS)

# Build ready for packaging.
# Once everyone has gcc8, we can use CC="gcc -ffile-prefix-map=$(pwd)=/home/clightning"
./configure --prefix=/usr CC="gcc -fdebug-prefix-map=$(pwd)=/home/clightning"
# libwally wants "python".  Seems to work to force it here.
make -j"$MAKEPAR" PYTHON_VERSION=3 VERSION="$VERSION"
# VERSION must be passed here too: the Makefile falls back to git describe,
# which inside the builder sees the checked-out commit, not the release tag.
# Without it, --force-version names the tarball but the binaries are stamped
# with the branch version.
make -j"$MAKEPAR" install DESTDIR=inst/ VERSION="$VERSION"

cd inst && tar --sort=name \
      --mtime="$MTIME 00:00Z" \
      --owner=0 --group=0 --numeric-owner -cvaf ../clightning-"$VERSION-$PLATFORM-$ARCH".tar.xz .
