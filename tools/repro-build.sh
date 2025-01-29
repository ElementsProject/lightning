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
    Ubuntu-20.04)
	cat > /tmp/SHASUMS <<EOF
f554697f01a6267127ef20e6eae4e8ed983507c816475ac72dbb8be26d94c796  /var/cache/apt/archives/autoconf_2.69-11.1_all.deb
a517394d9dce4a4cc734e45d5b9b5f17fe43d6682843f480b942426736d12050  /var/cache/apt/archives/automake_1%3a1.16.1-4ubuntu6_all.deb
716a1922077df772dcd8d4e462e1c5a9570c48871cbee062c23ae348b3a08fa1  /var/cache/apt/archives/autotools-dev_20180224.1_all.deb
3ba573c01939749cbe8a315fee33f49e7bcf8ff23b024e4230fe6d45f85b2a15  /var/cache/apt/archives/gcc-9-base_9.3.0-10ubuntu2_amd64.deb
22f0282dc1549a4f5715b94e9c71ed0e96c400d522ec15453e1a8000d45ea8d7  /var/cache/apt/archives/gcc-9_9.3.0-10ubuntu2_amd64.deb
78ab6a8841c68300ba39992e8e33190371e133b3592c601ed3052d54e2ba59ea  /var/cache/apt/archives/gcc_4%3a9.3.0-1ubuntu2_amd64.deb
51bf3e807747de738435e9aa4213f43ec62769d7178614e4db9de387446c714e  /var/cache/apt/archives/libc-dev-bin_2.31-0ubuntu9_amd64.deb
adb78f38fb00c76af4384be7a4c5f41da242e05bea6b0483e03b7e0c86738477  /var/cache/apt/archives/libc6-dev_2.31-0ubuntu9_amd64.deb
255ebc78828b1531f83038805dd918a8a60c017f939b07dd614b9fb7f7400df3  /var/cache/apt/archives/libcc1-0_10-20200411-0ubuntu1_amd64.deb
f0a41d8e8cf379dbbdfc43169f34851ed452b3581e72c6654f2e290caf4e1b20  /var/cache/apt/archives/libcrypt-dev_1%3a4.4.10-10ubuntu4_amd64.deb
d1db4de59b4184e502407a2abfde23ed1a966e590f17b4d206bdb4fbb7df0040  /var/cache/apt/archives/libgcc-9-dev_9.3.0-10ubuntu2_amd64.deb
b1d9556fea9ed94dea7eeebeccc59bf9598a658e77e6dba5b9197d0f1a22059b  /var/cache/apt/archives/libpq-dev_12.2-4_amd64.deb
af86d031c99bc7db0c8e6a93547a885f48d1f88b683989ac479a9c1b2b9e1781  /var/cache/apt/archives/libpq5_12.2-4_amd64.deb
2bc3d45c379470ffbe6da5c30edd573c7579331299ad67a04af68f11b1858970  /var/cache/apt/archives/libsodium-dev_1.0.18-1_amd64.deb
2790af911186c8c8f34270199ac553ee43704f007d6af064205319d03b591f3c  /var/cache/apt/archives/libsodium23_1.0.18-1_amd64.deb
6d8f20d36b47a2ebc64c1cdd09acbe98c2786ee6f6ef49c84e0277e5b5453709  /var/cache/apt/archives/libsqlite3-0_3.31.1-4_amd64.deb
7b81b1f3c1b811b12ce7fa23cc4dc7e1e45700a158a674a2eb7ee6f5a4f10f2f  /var/cache/apt/archives/libsqlite3-dev_3.31.1-4_amd64.deb
a7d59420134a8307eb11ef79b68e2b35cadc794a60f82c87f4583e37c763fd01  /var/cache/apt/archives/linux-libc-dev_5.4.0-26.30_amd64.deb
1ffa955ebb58829f3ab0debf7ad57b150887f6a44769edbaef68b8da9d95f306  /var/cache/apt/archives/m4_1.4.18-4_amd64.deb
41e534af98cdb6219bc98fa4276d9c928a0862b8b373d49ee1fbe0ae5db64dc2  /var/cache/apt/archives/make_4.2.1-1.2_amd64.deb
9cd69c847d7b12bd9cb2c58afe8bd17fb3973361716af71eb45c0f2b6d7e6884  /var/cache/apt/archives/zlib1g-dev_1%3a1.2.11.dfsg-2ubuntu1_amd64.deb
EOF
	;;
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
f11b4d687a305dd7ee47a384d82a9bf04de913362df9efa67d2a029ae65051a9  /var/cache/apt/archives/libsodium-dev_1.0.18-1build3_amd64.deb
ce9a34ae09d8f3c8ec13c9e23372c029894e840f3fa1ce5d6bb41f58e9164d91  /var/cache/apt/archives/libsqlite3-dev_3.45.1-1ubuntu2.1_amd64.deb
9d1d707179675d38e024bb13613b1d99e0d33fa6c45e5f3bcba19340781781d3  /var/cache/apt/archives/libtool_2.4.7-7build1_all.deb
1fe6a815b56c7b6e9ce4086a363f09444bbd0a0d30e230c453d0b78e44b57a99  /var/cache/apt/archives/make_4.3-4.1build2_amd64.deb
023cbe9dbf0af87f10e54e342c67571874e412b9950d89c6cd7b010be2e67c3c  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg-3.1ubuntu2.1_amd64.deb
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
make PYTHON_VERSION=3 VERSION="$VERSION"
make install DESTDIR=inst/

cd inst && tar --sort=name \
      --mtime="$MTIME 00:00Z" \
      --owner=0 --group=0 --numeric-owner -cvaf ../clightning-"$VERSION-$PLATFORM-$ARCH".tar.xz .
