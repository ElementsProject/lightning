#! /bin/sh

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
db854b9af0f94eded5039830177f57a5b2d529f76e2b5b0de8ec0b26f7aedc83  /var/cache/apt/archives/gcc-11-base_11.2.0-19ubuntu1_amd64.deb
0320b98a2d4664b10f6de2ec3f3e2409cb8c3dbec8c32d938a6beaa78e1fed76  /var/cache/apt/archives/gcc-11_11.2.0-19ubuntu1_amd64.deb
0fbbb920bb9b3b24c357cca9035671fcfee5f9ed49175f6145db979406dbc532  /var/cache/apt/archives/libc-bin_2.35-0ubuntu3_amd64.deb
cc37cab5c60bcfe4bbf289a8002f369949a41ed46e8b51a0503a001099370c56  /var/cache/apt/archives/libc6-dev_2.35-0ubuntu3_amd64.deb
2f52cdc0aca888bb3995d871a65282107dc7c2a0a4d78f60680f709bdc0875aa  /var/cache/apt/archives/libcc1-0_12-20220319-1ubuntu1_amd64.deb
a79be2f6e45823dcc09e04d5e98c88ec88d07d5b8895d05b875a8ade8b345efa  /var/cache/apt/archives/libcrypt-dev_1%3a4.4.27-1_amd64.deb
adae5a301c7899c1bce8ae26b5423716a47e516df25c09d6d536607bc34853bc  /var/cache/apt/archives/libgcc-11-dev_11.2.0-19ubuntu1_amd64.deb
d8b8653388e676a3ae2fcf565c2b1a42a01a1104062317f641e8d24f0eaff9c3  /var/cache/apt/archives/libpq-dev_14.2-1ubuntu1_amd64.deb
542dcee1409c74d03ecdd4ca4a0cfd467e5d2804d9985b58e39d3c5889a409e3  /var/cache/apt/archives/libpq5_14.2-1ubuntu1_amd64.deb
885ee09c37d0e37ef6042e8cb4a22ccbab92101f21ab0c8f51ae961e4484407c  /var/cache/apt/archives/libsodium23_1.0.18-1build2_amd64.deb
09584c8ab2f840bf3db4a5763f6e4b450688aa8879acd4c8f4c1942375b9ca57  /var/cache/apt/archives/libsodium-dev_1.0.18-1build2_amd64.deb
000a1d5c0df0373c75fadbfea604afb6b1325bf866a3ce637ae0138abe6d556d  /var/cache/apt/archives/libsqlite3-0_3.37.2-2_amd64.deb
1b2a93020593c9e94a25f750ce442da5a6e8ff48a20f52cec92dfc3fa35336d8  /var/cache/apt/archives/linux-libc-dev_5.15.0-25.25_amd64.deb
572a544d2c18bf49d25c465720c570cd8e6e38731386ac9c0a7f29bed2486f3e  /var/cache/apt/archives/m4_1.4.18-5ubuntu2_amd64.deb
080b79a1a1623a2e6c6eead37d62b15fdf2c3dbfeafe8ecf5e31c54eb09eadcc  /var/cache/apt/archives/make_4.3-4.1build1_amd64.deb
52449467942cc943d651fd16867014e9339f3657935fc09b75b3347aa5a78066  /var/cache/apt/archives/zlib1g_1%3a1.2.11.dfsg-2ubuntu9_amd64.deb
5722d6ef8435a9dc3736e474040b4c7e6512b889ad9f74b6d52cdf11eec7e219  /var/cache/apt/archives/libsqlite3-dev_3.37.2-2_amd64.deb
ddbadadcbfe2669de79eabac36a990f0f1666bb86a87d1a9cd56fd72620ca2db  /var/cache/apt/archives/zlib1g-dev_1%3a1.2.11.dfsg-2ubuntu9_amd64.deb
59e3890fc8407bcf8ccc9f709d6513156346d5c942e8c624dc90435e58f6f978  /var/cache/apt/archives/automake_1%3a1.16.5-1.3_all.deb
EOF
	;;
    Ubuntu-24.04)
	cat > /tmp/SHASUMS <<EOF
cc3f9f7a1e576173fb59c36652c0a67c6426feae752b352404ba92dfcb1b26c9  /var/cache/apt/archives/autoconf_2.71-3_all.deb
5ae9a98e73545002cd891f028859941af2a3c760cb6190e635c7ef36953912de  /var/cache/apt/archives/automake_1%3a1.16.5-1.3ubuntu1_all.deb
0e0bb8b25153ed1c44ab92bc219eed469fcb5820c5c0bc6454b2fd366a33d3ee  /var/cache/apt/archives/gcc_4%3a13.2.0-7ubuntu1_amd64.deb
bd3e8cd6ab8cf731d8a8a15333831b9081a94ebefe22236fc8713975fe7a6d3a  /var/cache/apt/archives/libsodium-dev_1.0.18-1ubuntu0.24.04.1_amd64.deb
5131ce3d7cdb7193bcef1b402741a0e0f436e25a50e65443fffcc7064e2cd780  /var/cache/apt/archives/libsqlite3-dev_3.45.1-1ubuntu2.5_amd64.deb
9d1d707179675d38e024bb13613b1d99e0d33fa6c45e5f3bcba19340781781d3  /var/cache/apt/archives/libtool_2.4.7-7build1_all.deb
1fe6a815b56c7b6e9ce4086a363f09444bbd0a0d30e230c453d0b78e44b57a99  /var/cache/apt/archives/make_4.3-4.1build2_amd64.deb
023cbe9dbf0af87f10e54e342c67571874e412b9950d89c6cd7b010be2e67c3c  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg-3.1ubuntu2.1_amd64.deb
EOF
	;;
    Ubuntu-26.04)
    cat > /tmp/SHASUMS <<EOF
9edd0db0fa94580ab013529d6842a8e89b8ed22ab337da5e95cbb43971978815  /var/cache/apt/archives/autoconf_2.72-3.1ubuntu2_all.deb
1a443abf03a5af97f4493405e22eba52fd6935a8b0583ac32fb88b3727563e53  /var/cache/apt/archives/automake_1%3a1.18.1-3build1_all.deb
d780844418b745c432a5d6c85f055625f37e27523b026baee0c87d386a0aab0a  /var/cache/apt/archives/gcc_4%3a15.2.0-5ubuntu1_amd64.deb
34e8337b30160458f44bada750c9e94ec18ec5ac087e2428043ddb04625226cc  /var/cache/apt/archives/libsodium-dev_1.0.18-2_amd64.deb
0f57948b8c1d4f369f14dc3897d4985227020d57b798a7ddd1b9acb2a8ea430d  /var/cache/apt/archives/libsqlite3-dev_3.46.1-9_amd64.deb
5b3146cd9d380e4725fc5b5e54795ae1f72d165d93e68ce29076b69762661fd4  /var/cache/apt/archives/libtool_2.5.4-9_all.deb
a86f39d57a32b7c919c0ad721fc2f17ab533a42fda348c8d81a4eea1577a014f  /var/cache/apt/archives/make_4.4.1-3_amd64.deb
601b9f92a04ea9ff7de6f60f60c34f2e2743f9c478125ac9e413f29a1fa728d9  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg+really1.3.1-1ubuntu3_amd64.deb
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
make -j"$MAKEPAR" install DESTDIR=inst/

cd inst && tar --sort=name \
      --mtime="$MTIME 00:00Z" \
      --owner=0 --group=0 --numeric-owner -cvaf ../clightning-"$VERSION-$PLATFORM-$ARCH".tar.xz .
