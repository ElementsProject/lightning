#! /bin/sh

set -e

LANG=C
LC_ALL=C
export LANG LC_ALL

for arg; do
    case "$arg" in
	--force-mtime=*)
	    FORCE_MTIME=${arg#*=}
	    ;;
	--help)
	    echo "Usage: [--force-mtime=YYYY-MM-DD]"
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

PLATFORM="$OS"-"$VER"
VERSION=$(git describe --always --dirty=-modded --abbrev=7 2>/dev/null || pwd | sed -n 's,.*/clightning-\(v[0-9.rc\-]*\)$,\1,p')

# eg. ## [0.6.3] - 2019-01-09: "The Smallblock Conspiracy"
# Skip 'v' here in $VERSION
MTIME=${FORCE_MTIME:-$(sed -n "s/^## \\[${VERSION#v}\\] - \\([-0-9]*\\).*/\\1/p" < CHANGELOG.md)}
if [ -z "$MTIME" ]; then
    echo "No date found for $VERSION in CHANGELOG.md" >&2
    exit 1
fi

case "$PLATFORM" in
    Ubuntu-18.04)
	# Use an ISO base of 5748706937539418ee5707bd538c4f5eabae485d17aa49fb13ce2c9b70532433 /home/rusty/Downloads/ubuntu-18.04.1-desktop-amd64.iso
	# Check they've turned off updates and security updates
	if grep ^deb /etc/apt/sources.list | grep -- '-\(updates\|security\)'; then
	    echo Please disable security and updates in /etc/apt/sources.list >&2
	    exit 1
	fi
	DOWNLOAD='sudo apt -y --no-install-recommends --reinstall -d install'
	PKGS='autoconf automake libtool make gcc libgmp-dev libsqlite3-dev zlib1g-dev libsodium-dev'
	INST='sudo dpkg -i'
	cat > /tmp/SHASUMS <<EOF
a909ad8b2e97f45960a05458140cff737df30bf7c616778a5a0ca74b9d012d93  /var/cache/apt/archives/autoconf_2.69-11_all.deb
d25ff344a7b808ef3ef8a3717cdad8f589ad20b57ea954054e9cc016fe7dff01  /var/cache/apt/archives/automake_1%3a1.15.1-3ubuntu2_all.deb
716a1922077df772dcd8d4e462e1c5a9570c48871cbee062c23ae348b3a08fa1  /var/cache/apt/archives/autotools-dev_20180224.1_all.deb
abe8f767884414dde79c4c5c4b6b7447ce057a07277a6de24f1b96e7e2b5da5a  /var/cache/apt/archives/gcc_4%3a7.3.0-3ubuntu2_amd64.deb
e8d83c288e08da39c5ccd289b550e2097f562bf848480f71f94cebbd187e60da  /var/cache/apt/archives/gcc-7_7.3.0-16ubuntu3_amd64.deb
92f5f15faca8cee48608b58a0300c469c076dd1dd8946b93b8428abd404d54f9  /var/cache/apt/archives/libasan4_7.3.0-16ubuntu3_amd64.deb
fc386b12f324c34e405502767216daef22bf7d2f0e597b1c7ccea5cef1821bd3  /var/cache/apt/archives/libatomic1_8-20180414-1ubuntu2_amd64.deb
e426c70a940a7d0c5c95823a5fd01f26bd8bcb08d109df2f8c96c439da8dc440  /var/cache/apt/archives/libc6-dev_2.27-3ubuntu1_amd64.deb
69ea1317b37cbd467eb7d216f5d23aa8831d926908e9e12477aa28bdc1d5e62b  /var/cache/apt/archives/libc-dev-bin_2.27-3ubuntu1_amd64.deb
357185ad09d689b61efda9576888feea2a0f178ae1422cddc6cd0d48f7c22d50  /var/cache/apt/archives/libcilkrts5_7.3.0-16ubuntu3_amd64.deb
becbeba33d3824aa3c0d1b1e62653fcee776eb7cad631df0748fa77032e293c6  /var/cache/apt/archives/libgcc-7-dev_7.3.0-16ubuntu3_amd64.deb
77066044de14fbcc4f2326348e24dda33e1106295e9c44748bb457ecd132b823  /var/cache/apt/archives/libgmp-dev_2%3a6.1.2+dfsg-2_amd64.deb
612ab92cdf2aef4591c3a36e1656e3af9a3fe056989e2ac22e5482017208f736  /var/cache/apt/archives/libgmpxx4ldbl_2%3a6.1.2+dfsg-2_amd64.deb
445b4569e2d3b72403ce3f79a58021f7d2832ee1e5e1a8e9fea7ab9aadaa0f1c  /var/cache/apt/archives/libitm1_8-20180414-1ubuntu2_amd64.deb
4aa713aae73c15f3cc968b45cac3b0ae4e5d8c0b39ec35a6a535672fd833eb75  /var/cache/apt/archives/liblsan0_8-20180414-1ubuntu2_amd64.deb
1bded2761c1213cc3b6bab27f515abff895af51d4b2272d6bddeadbf067a30dc  /var/cache/apt/archives/libmpx2_8-20180414-1ubuntu2_amd64.deb
e06e02b5f1c7bb418ba2f3c6d1ec9f64368178f8f6e5e937d7bbc8017fc8923e  /var/cache/apt/archives/libquadmath0_8-20180414-1ubuntu2_amd64.deb
233ba112b0c15cc602c6d5537ae427531228d78a0586dc8d39d5b6aac47921c1  /var/cache/apt/archives/libsigsegv2_2.12-1_amd64.deb
bcd2b6427252cd9c0eff68662f4ceb81f21ff74239ed01f56694b1e3f0a75649  /var/cache/apt/archives/libsodium-dev_1.0.16-2_amd64.deb
48a8767f36cb96d8c9dbb1f6f898a51943119dc8d6eb720c1285a5939cb43fb1  /var/cache/apt/archives/libsqlite3-dev_3.22.0-1_amd64.deb
961648481e22bbc5004c36537761327e6d3ee8daacc78df75054771b1296dd5e  /var/cache/apt/archives/libtool_2.4.6-2_all.deb
a3aeef76c96263e041a9c2c93616717072ff702d328c7987791ba4580c863698  /var/cache/apt/archives/libtsan0_8-20180414-1ubuntu2_amd64.deb
87c1fa125edff484a04267fd6dd21098e3fd9de74a669b804d44853c925a4893  /var/cache/apt/archives/libubsan0_7.3.0-16ubuntu3_amd64.deb
4a73fc5ea2d0284e9c9c84cba68cbe5880505afbae0a3201c65c336daf8f8239  /var/cache/apt/archives/linux-libc-dev_4.15.0-20.21_amd64.deb
eb49ad0a92f46080ab23974ee5db69dc08709a74e4275a0906afc220c75ce7a8  /var/cache/apt/archives/m4_1.4.18-1_amd64.deb
6a7f7b7ad1f6ff6332099ed9ceaa4889a6ce56a7a48817ddccc0952126059d07  /var/cache/apt/archives/make_4.1-9.1ubuntu1_amd64.deb
1bd6bfc66d1de113f14a9afdd61d7f4b911c11c570403dd9785aa937b88f9ea9  /var/cache/apt/archives/zlib1g-dev_1%3a1.2.11.dfsg-0ubuntu2_amd64.deb
EOF
	;;
    Ubuntu-20.04)
	if grep ^deb /etc/apt/sources.list | grep -- '-\(updates\|security\)'; then
	    echo Please disable security and updates in /etc/apt/sources.list >&2
	    exit 1
	fi
	DOWNLOAD='sudo apt -y --no-install-recommends --reinstall -d install'
	PKGS='autoconf automake libtool make gcc libgmp-dev libsqlite3-dev zlib1g-dev libsodium-dev'
	INST='sudo dpkg -i'
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
8dd29cf74e89d8555c6057345d40b1e501407ff6ac3a13de35ef8fa5ae6cb300  /var/cache/apt/archives/libgmp-dev_2%3a6.2.0+dfsg-4_amd64.deb
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
make PYTHON_VERSION=3
make install DESTDIR=inst/

cd inst && tar --sort=name \
      --mtime="$MTIME 00:00Z" \
      --owner=0 --group=0 --numeric-owner -cvaf ../clightning-"$VERSION-$PLATFORM".tar.xz .
