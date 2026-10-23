#! /bin/sh
# ARMv7 (32-bit, hard float) variant of repro-build.sh.
# Unlike the amd64 and arm64 scripts this one cross-compiles: it runs in the
# amd64 builder image and uses Ubuntu's arm-linux-gnueabihf toolchain plus
# armhf libraries from ports.ubuntu.com, all pinned below.  A native armv7
# build is not possible: the vendored protoc used by cln-grpc has no armv7
# binary.
#
# The build runs a few armv7 programs (configure tests, tools/headerversions),
# so the host needs qemu-arm registered with binfmt_misc, e.g.
#   docker run --privileged --rm tonistiigi/binfmt --install arm

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

ARCH=armv7
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

# Same release pocket as the main archive (updates and security are disabled
# above), but armhf lives on the ports mirror.
# VERSION_CODENAME comes from /etc/os-release, sourced above.
CODENAME=${VERSION_CODENAME:?no VERSION_CODENAME in /etc/os-release}
sudo dpkg --add-architecture armhf
sudo sed -i 's/^deb \(http\)/deb [arch=amd64] \1/' /etc/apt/sources.list
echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports $CODENAME main universe" | sudo tee -a /etc/apt/sources.list
sudo apt-get update

DOWNLOAD='sudo apt -y --no-install-recommends --reinstall -d install'
PKGS='autoconf automake libtool make gcc-arm-linux-gnueabihf libc6-dev:armhf libsqlite3-dev:armhf zlib1g-dev:armhf libsodium-dev:armhf libpq-dev:armhf'
INST='sudo dpkg -i'

case "$PLATFORM" in
    Ubuntu-22.04)
	cat > /tmp/SHASUMS <<EOF
96b528889794c4134015a63c75050f93d8aecdf5e3f2a20993c1433f4c61b80e  /var/cache/apt/archives/autoconf_2.71-2_all.deb
59e3890fc8407bcf8ccc9f709d6513156346d5c942e8c624dc90435e58f6f978  /var/cache/apt/archives/automake_1%3a1.16.5-1.3_all.deb
74d8adcd6e48a7e939e01b0303e7a7e7c9239e1a9cdf1bd57af6cb4ef4fd76ff  /var/cache/apt/archives/binutils-arm-linux-gnueabihf_2.38-3ubuntu1_amd64.deb
5c891af83e612f68ae3197bf4ab56c0fd1588a16fb184c7fe311f044a3835746  /var/cache/apt/archives/cpp-11-arm-linux-gnueabihf_11.2.0-17ubuntu1cross1_amd64.deb
05aa81a4e744a5620b6a5bac9f42e49794a658831bf337d869b5ab25b08afc71  /var/cache/apt/archives/cpp-arm-linux-gnueabihf_4%3a11.2.0-1ubuntu1_amd64.deb
cf9fee9eddce8e0095039bcea2cfd88e8ac471cbec57b9c02dbc176a050ac1ad  /var/cache/apt/archives/gcc-11-arm-linux-gnueabihf-base_11.2.0-17ubuntu1cross1_amd64.deb
08898df1b8bd57f6882e327559c9a539b6a918cf06abe5022f546f8da9d85445  /var/cache/apt/archives/gcc-11-arm-linux-gnueabihf_11.2.0-17ubuntu1cross1_amd64.deb
8eb857c9f6651c97a081afb35a08e282aa36a49f6e755be8d4959ccf2005eb7f  /var/cache/apt/archives/gcc-11-cross-base_11.2.0-17ubuntu1cross1_all.deb
204d717f318a9c59061bdf49a2ea23f820cda9e3e27e680bbd7aec1eb9c6719c  /var/cache/apt/archives/gcc-12-base_12-20220319-1ubuntu1_armhf.deb
482ca2b7bc44d6cf105c50bb162a4d8c1126ccb05a5da01aad54d221c7eeb3c2  /var/cache/apt/archives/gcc-12-cross-base_12-20220222-1ubuntu1cross1_all.deb
4b7467bcb46a5531ef2a9bd6597426835d1b2382a0c994ec956f9fa125fb28c1  /var/cache/apt/archives/gcc-arm-linux-gnueabihf_4%3a11.2.0-1ubuntu1_amd64.deb
31894855b2e1c9d6b2bc1f639a54293528cf1cee07412c12c086e326454544f2  /var/cache/apt/archives/libasan6-armhf-cross_11.2.0-17ubuntu1cross1_all.deb
71b98cd74bf1583ce5c74cb3f198ac85b01692d1328277459b0fe017db39a8ff  /var/cache/apt/archives/libatomic1-armhf-cross_12-20220222-1ubuntu1cross1_all.deb
c1b97d741dfb346cbafad6e6f595aa94b281cd012beb13a7a30299f6b8375cf9  /var/cache/apt/archives/libc6-armhf-cross_2.35-0ubuntu1cross3_all.deb
7e1b52cd128556e0da01da9e5a309a1a0fb03b886c6bb4f4c92ef9e5fc91bf8a  /var/cache/apt/archives/libc6-dev_2.35-0ubuntu3_armhf.deb
7ff07430baf2426fd49d5ba641cfebbb381181e453bf1634b791b7de9d65e104  /var/cache/apt/archives/libc6_2.35-0ubuntu3_armhf.deb
34cbf1310acaf664027fd313739c17a0113686d3020bae86b43ea7a000d53c3e  /var/cache/apt/archives/libcom-err2_1.46.5-2ubuntu1_armhf.deb
8a3191b48066475c1c7a635da49aa624d742cdbf58e7b4114d65d5000e5de68d  /var/cache/apt/archives/libcrypt-dev_1%3a4.4.27-1_armhf.deb
d5fa3df6ba1f3860931e4933f14b8329e1cf50fa5925c06da34da82e707aac28  /var/cache/apt/archives/libcrypt1_1%3a4.4.27-1_armhf.deb
4fd634b8baf78a65ed8fd74dfab52f070cd0f886ddc469076a0f792348f8d1c4  /var/cache/apt/archives/libdb5.3_5.3.28+dfsg1-0.8ubuntu3_armhf.deb
e8a2daff4724cff9362696ece48fef3589b18ff8d145c0d758c78213c80c38d7  /var/cache/apt/archives/libffi8_3.4.2-4_armhf.deb
ad3f8f1cafdd7ffd1001e5f3fc7e35262b3d03063794883e153435c46e010bd8  /var/cache/apt/archives/libgcc-11-dev-armhf-cross_11.2.0-17ubuntu1cross1_all.deb
0365c2a8a9551f25c8031961847e5be9de945f22cceff84ba401638dc8eea755  /var/cache/apt/archives/libgcc-s1-armhf-cross_12-20220222-1ubuntu1cross1_all.deb
87474df2476fb40df114efe178518b18624e94622d735590beee3a54963bb1cf  /var/cache/apt/archives/libgcc-s1_12-20220319-1ubuntu1_armhf.deb
8a05c72e504837978ca7e8cf37907199bbc44e6c3e7afa802ce2e30a1279e8ff  /var/cache/apt/archives/libgmp10_2%3a6.2.1+dfsg-3ubuntu1_armhf.deb
7758e07a96acdda3740d53d86297c116ebe2e491f6fe91616e044ac1d6a089da  /var/cache/apt/archives/libgnutls30_3.7.3-4ubuntu1_armhf.deb
176ac04fff357d66e842a1f5d92333567c473da43f293be11d964e0991e0a846  /var/cache/apt/archives/libgomp1-armhf-cross_12-20220222-1ubuntu1cross1_all.deb
5572fdb489332b240766355a5bdbc2e497f2ff40782f1bac080556a20cc1def5  /var/cache/apt/archives/libgssapi-krb5-2_1.19.2-2_armhf.deb
2684732854a4ec0ac48a6d3d52006246e704d5363e467e312672d350cd2a32c5  /var/cache/apt/archives/libhogweed6_3.7.3-1build2_armhf.deb
833b6faaa5cca3961bc588b20509ae327c894d058700c71210eab0c2f16052ef  /var/cache/apt/archives/libidn2-0_2.3.2-2build1_armhf.deb
ad77d23e0f8fe7f4cf29c4c7dc59936c0c3f1e6d49e96ae93d081e8657522822  /var/cache/apt/archives/libk5crypto3_1.19.2-2_armhf.deb
36a1880c0d0c1a45f153e742e3a66d8426ec7f72a9f202ba5d17ef57dd696998  /var/cache/apt/archives/libkeyutils1_1.6.1-2ubuntu3_armhf.deb
1d52530b0f7943dde50cbfbac7f63dbbfecd79abe273bd76787ee3e1ff45b0f4  /var/cache/apt/archives/libkrb5-3_1.19.2-2_armhf.deb
ece0fa96d6337b06c0c0ae57a889c8fbc1700c9eb0c6100e689039906577ecb7  /var/cache/apt/archives/libkrb5support0_1.19.2-2_armhf.deb
9e2f7f893d88125109adc59ec2f689f3c4bc9992856a1577deb16aaf3b509c93  /var/cache/apt/archives/libldap-2.5-0_2.5.11+dfsg-1~exp1ubuntu3_armhf.deb
54606360e0111e2ce918528a09b3e2241e3b4eda6d60651e1fbad4c764bda7da  /var/cache/apt/archives/libnettle8_3.7.3-1build2_armhf.deb
e062f359b8ec6d6b70d33b3852dc9ce38d3d9bc13e14d31d300c496c47f28990  /var/cache/apt/archives/libnsl-dev_1.3.0-2build2_armhf.deb
c599752a67feffbb6b66897f77ab2b2d0cc2f41190998fe2495ef157dbcd78f7  /var/cache/apt/archives/libnsl2_1.3.0-2build2_armhf.deb
caa7db89a9f775534aab37fd086cacd1657f7057d52c3f1a033fb585b783af65  /var/cache/apt/archives/libp11-kit0_0.24.0-6build1_armhf.deb
b360ae1adff746d519bacc5369101d9074019df9fd82276fdc8be7a33a44c147  /var/cache/apt/archives/libpq-dev_14.2-1ubuntu1_armhf.deb
2d8b52936daf8431a5a8b77deeba92a837009fcfd5c92e15159e098285076e7d  /var/cache/apt/archives/libpq5_14.2-1ubuntu1_armhf.deb
6d5437b83bc243c2b23a258ad577426beacb60ee9cef7cc4dacb2d3cbde2d699  /var/cache/apt/archives/libsasl2-2_2.1.27+dfsg2-3ubuntu1_armhf.deb
3df327dcff508915d132e311201d531b88e473a93817d33ab4e2377e3af6615d  /var/cache/apt/archives/libsasl2-modules-db_2.1.27+dfsg2-3ubuntu1_armhf.deb
b90d7af8a0a01770526865b3380a7c54b11e80cd58a6cff929768d53b8bb9905  /var/cache/apt/archives/libsodium-dev_1.0.18-1build2_armhf.deb
248092390466ac29dd75cb4e4f5252ee1def29140f9fc4481d7f89d1d481f2fa  /var/cache/apt/archives/libsodium23_1.0.18-1build2_armhf.deb
4ffc3cc97b2ff05eb2e9749bc668d6f35cc32772315bb34b2a1dc93a51969fb9  /var/cache/apt/archives/libsqlite3-0_3.37.2-2_armhf.deb
1e302e000f5df9b7f69e4b4302b5809c8bff52f2d04014e1f103c6e29f6524e3  /var/cache/apt/archives/libsqlite3-dev_3.37.2-2_armhf.deb
6c8e783eafdb4716a978581dae96c70dcbc40f89e93a9761d40691aaa40757dd  /var/cache/apt/archives/libssl-dev_3.0.2-0ubuntu1_armhf.deb
b5e72385c2b0e3fd9157e2b9c2d966ee410cdc626d1bd1a3e1d6de1d4f485bc5  /var/cache/apt/archives/libssl3_3.0.2-0ubuntu1_armhf.deb
ae147584b23c48b9d888ccad0633d9ad7720aca64926970d427189fec9cfcffb  /var/cache/apt/archives/libstdc++6-armhf-cross_12-20220222-1ubuntu1cross1_all.deb
42607a682ee8eecebf2a9464355529b9f96386cf861c28bee8a598fb9ed716b6  /var/cache/apt/archives/libtasn1-6_4.18.0-4build1_armhf.deb
2f871c0960b7deace4b81e0760df40915f1a451b0748fee65168a358a04a3c04  /var/cache/apt/archives/libtirpc-dev_1.3.2-2build1_armhf.deb
48478f1157dce2b856c2a9c493ff1d25968e99bdb36ad0af464d02afda236f18  /var/cache/apt/archives/libtirpc3_1.3.2-2build1_armhf.deb
fb994bc0152f4e77a791b51bc54fd5e38963aa6473e60c45369ef373b6119124  /var/cache/apt/archives/libtool_2.4.6-15build2_all.deb
86fa6f4b1ceb57843a23ca8851af5c42da0f2f0f486a6120fe4ebfdd48957a54  /var/cache/apt/archives/libubsan1-armhf-cross_12-20220222-1ubuntu1cross1_all.deb
a3ace833fbfe1f63bbf774a8f46a763d4aa9cd65b11c6b12ea51d744d6a79be2  /var/cache/apt/archives/libunistring2_1.0-1_armhf.deb
c49b6f5398a04b19f3bb3dd7edfcf529dce87ae67fb45a2a244420e5a5aacd47  /var/cache/apt/archives/linux-libc-dev_5.15.0-25.25_armhf.deb
080b79a1a1623a2e6c6eead37d62b15fdf2c3dbfeafe8ecf5e31c54eb09eadcc  /var/cache/apt/archives/make_4.3-4.1build1_amd64.deb
3a58d258d27cc25ba35159d9baf0a0edcb30084be5b2af159088949927e35544  /var/cache/apt/archives/zlib1g-dev_1%3a1.2.11.dfsg-2ubuntu9_armhf.deb
fa227e5f5b3310b63ac317f9bf002cdb358e42de0eef093cdc0364cce92490c8  /var/cache/apt/archives/zlib1g_1%3a1.2.11.dfsg-2ubuntu9_armhf.deb
EOF
	;;
    Ubuntu-24.04)
	cat > /tmp/SHASUMS <<EOF
cc3f9f7a1e576173fb59c36652c0a67c6426feae752b352404ba92dfcb1b26c9  /var/cache/apt/archives/autoconf_2.71-3_all.deb
5ae9a98e73545002cd891f028859941af2a3c760cb6190e635c7ef36953912de  /var/cache/apt/archives/automake_1%3a1.16.5-1.3ubuntu1_all.deb
04fe0cda23afaf185fd4ec7edbfac8afda9008c4ddc6898ccb6aca8f4b5eeb7d  /var/cache/apt/archives/binutils-arm-linux-gnueabihf_2.42-4ubuntu2_amd64.deb
a6bab4ba1641b40871f049e9ce534d85805b58f9083a48c352f93b7eebae7689  /var/cache/apt/archives/cpp-13-arm-linux-gnueabihf_13.2.0-23ubuntu4cross1_amd64.deb
64c3b896c8cad177c41e540cd8324ac60313371216b17eb78eba69caf19eedce  /var/cache/apt/archives/cpp-arm-linux-gnueabihf_4%3a13.2.0-7ubuntu1_amd64.deb
f55e2547444a1a2d2b8cc3277de6d4bc965c2ee53d38cea0d9d5917194c58788  /var/cache/apt/archives/gcc-13-arm-linux-gnueabihf-base_13.2.0-23ubuntu4cross1_amd64.deb
03e261f1e341e323cf63eb9c6b9636923f140a4268924fd8774872ce8dee63ef  /var/cache/apt/archives/gcc-13-arm-linux-gnueabihf_13.2.0-23ubuntu4cross1_amd64.deb
1a9adce5c298fa1ded7a9f3448d9cdbcd68c2b14e5d7a7f8b356a1ff54f37e91  /var/cache/apt/archives/gcc-13-cross-base_13.2.0-23ubuntu4cross1_all.deb
2fe15d034f6e0e7504f1e1635e3b55628c09c70eb3857a77f3b9eae8518eb03f  /var/cache/apt/archives/gcc-14-base_14-20240412-0ubuntu1_armhf.deb
4abeb95258bbaf5542d71d3483532529126d5773fe14e9a024f564b94b5d9d61  /var/cache/apt/archives/gcc-14-cross-base_14-20240412-0ubuntu1cross1_all.deb
d8628ea40a408311dd3ecabad1965e1775f47a1889fca888b07f10107381dabb  /var/cache/apt/archives/gcc-arm-linux-gnueabihf_4%3a13.2.0-7ubuntu1_amd64.deb
f5ca52b5c6bc6743a964c9ba678d7eea43c64c07e1c47af268534aa6cd6d95da  /var/cache/apt/archives/libasan8-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
a811378f78501e9fa7b342160398d29ce1aab745938c0024169fda63a235afc4  /var/cache/apt/archives/libatomic1-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
4c61c413e2cc45ce2c5703a1564d1886f45c98ddbbd33d9f8b05736dee045ce1  /var/cache/apt/archives/libc6-armhf-cross_2.39-0ubuntu8cross1_all.deb
47c4a7482e11f188870a9eccd9104016c445f90c6e737e7e6326726eefebe840  /var/cache/apt/archives/libc6-dev_2.39-0ubuntu8_armhf.deb
77aa11468315dc1241e24d7963d01512f81541e64d960c9d7685c380fb490b50  /var/cache/apt/archives/libc6_2.39-0ubuntu8_armhf.deb
2d59bae0f2d0ba057574a06e14475af4e501720756934bf3451ba0b8a687b0bd  /var/cache/apt/archives/libcom-err2_1.47.0-2.4~exp1ubuntu4_armhf.deb
58010a8f588477dae4444f3b92636ef4e02aa2d21ab4587d33702299163a5380  /var/cache/apt/archives/libcrypt-dev_1%3a4.4.36-4build1_armhf.deb
198990e999add09e21b0ab3522c94333a0e135656c7f00960f534cec15477a74  /var/cache/apt/archives/libcrypt1_1%3a4.4.36-4build1_armhf.deb
12ac2200cb3d8451b92d626d1733f5e72d832ceabb1d9b20cd5b04ab74079012  /var/cache/apt/archives/libdb5.3t64_5.3.28+dfsg2-7_armhf.deb
a5af6885f9b3f5e2910c767c74824c6415eeaaa54181bdfb31bdc6d481fc2bba  /var/cache/apt/archives/libffi8_3.4.6-1build1_armhf.deb
a1e27cfa0325649d1b7e026f80533739c66db4d28a7b3b9bf875305f9babca8f  /var/cache/apt/archives/libgcc-13-dev-armhf-cross_13.2.0-23ubuntu4cross1_all.deb
7c9d5ba79c69b9ea40b0b7b6a429f40e5d5525d72c74dc69545a823773d1de73  /var/cache/apt/archives/libgcc-s1-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
0c5b9ce5fe1f45b3b743c6fdc18c1d41eca56220a5df03e5c9a72f9c3414d3bd  /var/cache/apt/archives/libgcc-s1_14-20240412-0ubuntu1_armhf.deb
c9f5b7782608819532c8b7c480791f02e2913220488a88a0bf95eff452c29fb1  /var/cache/apt/archives/libgmp10_2%3a6.3.0+dfsg-2ubuntu6_armhf.deb
dd12a5df17e84c37d2a08917e16379a5eaa13ee9e67f40c751177e7b4451b4a4  /var/cache/apt/archives/libgnutls30t64_3.8.3-1.1ubuntu3_armhf.deb
b09a5d8f6a425ca1cada2d20d32543c5f2f8a99c3e2fb1cc982e86c5c2f3402c  /var/cache/apt/archives/libgomp1-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
d6a583b0af50535cb401953427a3a8c798bcbd2091f76a3f7f925cc61140f878  /var/cache/apt/archives/libgssapi-krb5-2_1.20.1-6ubuntu2_armhf.deb
e038eb5d755a1488dbb7c521f318f55a0750293b6fb71486d029f94e840c6f9f  /var/cache/apt/archives/libhogweed6t64_3.9.1-2.2build1_armhf.deb
13fe57406cfc24c15b9992f77af18d62ca2d8693fe0627ebeeb60136ae4ce1f4  /var/cache/apt/archives/libidn2-0_2.3.7-2build1_armhf.deb
7902f06a1bda378cb1a9bfafd8916487f9463f8dfc28c3e5a90ace1aa89a2680  /var/cache/apt/archives/libk5crypto3_1.20.1-6ubuntu2_armhf.deb
b7fbdce39f4c1e509936a58bb7dd16030e401afc8da8917b855ca77fb91d3a38  /var/cache/apt/archives/libkeyutils1_1.6.3-3build1_armhf.deb
04bbe5628d7237de592a96d011bd1279a4a65a1b8c980612d21f9e0b9dd814eb  /var/cache/apt/archives/libkrb5-3_1.20.1-6ubuntu2_armhf.deb
5ba23686e7cc066cdecaabc8000b21de5cf4c37d4f1090e19d58a2f65b18e66d  /var/cache/apt/archives/libkrb5support0_1.20.1-6ubuntu2_armhf.deb
ced9a8b5d9c28a5971d3711797b872fffc10303c07a0acec33034c0496ca045d  /var/cache/apt/archives/libldap2_2.6.7+dfsg-1~exp1ubuntu8_armhf.deb
e42190f8dc07e08a56a51dc5ffd9e706eb7a6091537830d866c775d773ff501f  /var/cache/apt/archives/libnettle8t64_3.9.1-2.2build1_armhf.deb
62363f55d00e882964fe8011001516afb3442180c85c1b80eb57ded249785eb1  /var/cache/apt/archives/libp11-kit0_0.25.3-4ubuntu2_armhf.deb
db3d3b572e2b71471338786363191eb76a8d4bb64c45cc39cef11bb0e3900a77  /var/cache/apt/archives/libpq-dev_16.2-1ubuntu4_armhf.deb
eb70fab21cecd6fd56afa27e7fd740111bcae7b4393472d27a14c782637853fd  /var/cache/apt/archives/libpq5_16.2-1ubuntu4_armhf.deb
098f891e009100d501b027b552baf66e6787f095a86e1085c4ad2ddb37e7dfa2  /var/cache/apt/archives/libsasl2-2_2.1.28+dfsg1-5ubuntu3_armhf.deb
64e6a8b037ff29c934e489365ee5ced370bf8e2c9d55c04607ca14ffb23b2e48  /var/cache/apt/archives/libsasl2-modules-db_2.1.28+dfsg1-5ubuntu3_armhf.deb
51eeb7c6ec0abca7d7c56380f00ac592051ecfcf4195e9838b128fcac863e740  /var/cache/apt/archives/libsodium-dev_1.0.18-1build3_armhf.deb
45b4403715d4058635e62a351b2bf95b0933895428c40d1636ff3e1038d02991  /var/cache/apt/archives/libsodium23_1.0.18-1build3_armhf.deb
876d648293a0376b3bb2de3ae2b01ef730ba8b67968a474cb865dd4f35a23075  /var/cache/apt/archives/libsqlite3-0_3.45.1-1ubuntu2_armhf.deb
8bfdb552386ec4577fa6b7300b8413a1223f2d53f780ce3a21ecfe13cd86428e  /var/cache/apt/archives/libsqlite3-dev_3.45.1-1ubuntu2_armhf.deb
d84e38b5476a064426f1c0abb2e770815a07af55e22cc23f216ecd2053603323  /var/cache/apt/archives/libssl-dev_3.0.13-0ubuntu3_armhf.deb
2fd586f776e78de2a5ca3be78785eae7651ea7552a9851213eed6c8878ddbf5c  /var/cache/apt/archives/libssl3t64_3.0.13-0ubuntu3_armhf.deb
ccabe2ee67dfb776ddbf693c69a9a40408e3fbed243f331243c8d0ecb5a3aa1b  /var/cache/apt/archives/libstdc++6-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
8a19fdac1cd60fbaf3d76ea9aa923acbfe76ec2ed2c37013b04488645143b62f  /var/cache/apt/archives/libtasn1-6_4.19.0-3build1_armhf.deb
9d1d707179675d38e024bb13613b1d99e0d33fa6c45e5f3bcba19340781781d3  /var/cache/apt/archives/libtool_2.4.7-7build1_all.deb
ce3c417e25dd92d5c6f50dce730da866b267c46d8d1a9d9e03c3869778473ba7  /var/cache/apt/archives/libubsan1-armhf-cross_14-20240412-0ubuntu1cross1_all.deb
69809eac19a0b176866c3d8290ffb6f1fe63af5c94a8d932ccb70e7b43dda5fa  /var/cache/apt/archives/libunistring5_1.1-2build1_armhf.deb
72dee1234a55b2894bdfbdf2d58583bcdbbf90c87a383b1b16272e848602e74b  /var/cache/apt/archives/linux-libc-dev_6.8.0-31.31_armhf.deb
1fe6a815b56c7b6e9ce4086a363f09444bbd0a0d30e230c453d0b78e44b57a99  /var/cache/apt/archives/make_4.3-4.1build2_amd64.deb
d085c375d6d4a558551dbdc897ad354126d4dffa604d2ac57d5099d7127ac2aa  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg-3.1ubuntu2_armhf.deb
df86f129cef95044bddc9cd920c1e0e478d42164c7323c4ec02a6a42b81324c6  /var/cache/apt/archives/zlib1g_1%3a1.3.dfsg-3.1ubuntu2_armhf.deb
EOF
	;;
    Ubuntu-26.04)
	cat > /tmp/SHASUMS <<EOF
9edd0db0fa94580ab013529d6842a8e89b8ed22ab337da5e95cbb43971978815  /var/cache/apt/archives/autoconf_2.72-3.1ubuntu2_all.deb
1a443abf03a5af97f4493405e22eba52fd6935a8b0583ac32fb88b3727563e53  /var/cache/apt/archives/automake_1%3a1.18.1-3build1_all.deb
929c3f39b2a50018ff177c02df4ba730f5516a17a92bf1ed5ee02c5895445768  /var/cache/apt/archives/binutils-arm-linux-gnueabihf_2.46-3ubuntu2_amd64.deb
46d663b3ff4888d2e53994dacc66d4b8ed06eacf6e1491bcdc4e0f08fd20c0b8  /var/cache/apt/archives/cpp-15-arm-linux-gnueabihf_15.2.0-16ubuntu1cross1_amd64.deb
fba23c69670b35ebf65dc982c05d733881bac66c9f2ab844074f057355a221b2  /var/cache/apt/archives/cpp-arm-linux-gnueabihf_4%3a15.2.0-5ubuntu1_amd64.deb
2cff1c4dfcd0234a5ab4b0db1c81df4070f220cbefe1278a8160e4ec2da8d3bd  /var/cache/apt/archives/gcc-15-arm-linux-gnueabihf-base_15.2.0-16ubuntu1cross1_amd64.deb
3077a8c6ca15ff2fd3307be7bfda852d1b6965993e8073d2cd01d6f0292f3fad  /var/cache/apt/archives/gcc-15-arm-linux-gnueabihf_15.2.0-16ubuntu1cross1_amd64.deb
0ba9491cc398eea08a962eaed3980942a2b34059e8f987fac1032523795a039d  /var/cache/apt/archives/gcc-15-cross-base_15.2.0-16ubuntu1cross1_all.deb
75e8ec3961a45b863bad033696bef0b9291a3f961c56ad457f2a3822a3d34a92  /var/cache/apt/archives/gcc-16-base_16-20260322-1ubuntu1_armhf.deb
3388f770c5eeda037bde05348ad744c47d02901b8f0f6f0066771c9678570556  /var/cache/apt/archives/gcc-16-cross-base_16-20260322-1ubuntu1cross1_all.deb
9f046cc9c160b7ae588fbfa5700433c77eecb947e77f24f624dada4ff8efc1fa  /var/cache/apt/archives/gcc-arm-linux-gnueabihf_4%3a15.2.0-5ubuntu1_amd64.deb
644b7042eb7eef0eef1c29dcbaddf2792c05e04883e94d7d81d0ffcdd906fc00  /var/cache/apt/archives/libasan8-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
b9ade21823076f86e94bc8f05909d05388dd2041723cc2fbf719d01e98ed640a  /var/cache/apt/archives/libatomic1-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
c6bbc3f2103a6c57ed7098b7af966b20dfb46af42f5c14bd3d2bee0c12cf76ed  /var/cache/apt/archives/libc-gconv-modules-extra_2.43-2ubuntu2_armhf.deb
9025e2fe97988e27606e3e44b68e0f73d4c569bf2a99d97b00211f833cc9fcbc  /var/cache/apt/archives/libc6-armhf-cross_2.43-2ubuntu2cross1_all.deb
83008eedf6c1b54f9c7269f71245c869fe051fea451825b06c812c6f123e977a  /var/cache/apt/archives/libc6-dev_2.43-2ubuntu2_armhf.deb
831bdee68fdb23ead2eb1c4a707cc2b81796336f890a3a809367cde998b5daba  /var/cache/apt/archives/libc6_2.43-2ubuntu2_armhf.deb
2e7b524a0336a3b30ba1a61f4038bc3d23cbc39085e124f5cf4335a93a0ade56  /var/cache/apt/archives/libcom-err2_1.47.2-3ubuntu4_armhf.deb
13fb1308eab44c12e4510f7562f39fc1442ce4eb92e3291d76c4470121382a5a  /var/cache/apt/archives/libdb5.3t64_5.3.28+dfsg2-10ubuntu1_armhf.deb
4070310a3b595c9cf905d68f37f755754f0509367ab3c4ed973c8a7ebea22f1e  /var/cache/apt/archives/libgcc-15-dev-armhf-cross_15.2.0-16ubuntu1cross1_all.deb
2706eecec31000b152dad5069490c5d01caad315f3d2ec05c100e06f7968c09d  /var/cache/apt/archives/libgcc-s1-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
79ca72801922eaab2b4491beea15557543c963f75c4161c9be6acf2b48c8e981  /var/cache/apt/archives/libgcc-s1_16-20260322-1ubuntu1_armhf.deb
a26477e8500a9dc92c38f186283f1b475d61fabfe2bb17c800ac066740025e10  /var/cache/apt/archives/libgomp1-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
9681dd934c657e4591bfef366bc080c63b84ec45b6e14a1ff932a87eab6c0054  /var/cache/apt/archives/libgssapi-krb5-2_1.22.1-2ubuntu4_armhf.deb
fe2824b87a761dd08bc04fcedd971b84b8ce03d2955a00a5f7f9ae8c7319ccec  /var/cache/apt/archives/libk5crypto3_1.22.1-2ubuntu4_armhf.deb
ba6ca48f7bf50da04ca05a366850318b037485b2b0889552fa3c8687c8e697a4  /var/cache/apt/archives/libkeyutils1_1.6.3-6ubuntu3_armhf.deb
d1d068284e5efed0a7853ed9066115f18df839a476cffe8a176a015de89c2545  /var/cache/apt/archives/libkrb5-3_1.22.1-2ubuntu4_armhf.deb
502e4c7faa93a57dae12a7acba613d58eaffe903fff81e393dad93b0a294c266  /var/cache/apt/archives/libkrb5support0_1.22.1-2ubuntu4_armhf.deb
956831b7f4cd9ececdd6ebde880b26aefb18f4ecf717b5b704209afe9b50a5e1  /var/cache/apt/archives/libldap2_2.6.10+dfsg-1ubuntu5_armhf.deb
4c76bebaf96da810204bd9df9dc99d458386fb7081adc1402fdde06784a0e985  /var/cache/apt/archives/libpq-dev_18.3-1_armhf.deb
40c53f5e146910e4f9cb4fb125477764b760625c3a8ffa3d29520939f407d27d  /var/cache/apt/archives/libpq5_18.3-1_armhf.deb
c7d359eab37b60fae5df324c64568748a4d70890d1b0aadd199d87550828b9b1  /var/cache/apt/archives/libsasl2-2_2.1.28+dfsg1-9ubuntu3_armhf.deb
d7773b9cd0f8e6de62504822df4f88dd329641ec2ebad3815b54b3c58cfe4119  /var/cache/apt/archives/libsasl2-modules-db_2.1.28+dfsg1-9ubuntu3_armhf.deb
dc2329cd7cf9046b546afb8b8c264c14fc2ecc2ebfb7562b15ca02c08b5f57d9  /var/cache/apt/archives/libsodium-dev_1.0.18-2_armhf.deb
92d69835d7178472440de132d9f09fb2af4289b18a9de2e3e4fe6b792c2ff0a1  /var/cache/apt/archives/libsodium23_1.0.18-2_armhf.deb
c9768c7c92736deebf752628419a3e0b0446128bd205cf77eee6d0b243faff89  /var/cache/apt/archives/libsqlite3-0_3.46.1-9_armhf.deb
aeb00846b3fd18dcb8c81d1abc8b51de94750601fb3c3890401b98b94e415436  /var/cache/apt/archives/libsqlite3-dev_3.46.1-9_armhf.deb
318396362cd572a43b629ec32649ffcb84a0ebf1e93356db1e603995de77e922  /var/cache/apt/archives/libssl-dev_3.5.5-1ubuntu3_armhf.deb
724e5470b289295abc5dad2d52be828d4576c7222ceca9676266e7842dc0c036  /var/cache/apt/archives/libssl3t64_3.5.5-1ubuntu3_armhf.deb
23e550073b91214769061fa6fff453e7cb228df2638c47a41cfb0b10f383ab83  /var/cache/apt/archives/libstdc++6-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
5b3146cd9d380e4725fc5b5e54795ae1f72d165d93e68ce29076b69762661fd4  /var/cache/apt/archives/libtool_2.5.4-9_all.deb
b0ad7c49650156bb4b12b998b6ccc87f6d764a1d6d4d2d08f57c7fb68d646d62  /var/cache/apt/archives/libubsan1-armhf-cross_16-20260322-1ubuntu1cross1_all.deb
5a341c4f3c183e2b823286068dedd8b435c95dc8850645ba1d3380b863323f69  /var/cache/apt/archives/libzstd1_1.5.7+dfsg-3_armhf.deb
1bfd3d8ca72df9795d24b25c73ef46afd75f3d208be7d07440116adbce800eac  /var/cache/apt/archives/linux-libc-dev_7.0.0-14.14_armhf.deb
a86f39d57a32b7c919c0ad721fc2f17ab533a42fda348c8d81a4eea1577a014f  /var/cache/apt/archives/make_4.4.1-3_amd64.deb
bb0b4249d442c1e456fd7a780012197c939d75a70e06aa780dd72be11fdc0c5f  /var/cache/apt/archives/zlib1g-dev_1%3a1.3.dfsg+really1.3.1-1ubuntu3_armhf.deb
d2c898b707c71795e62acd2875148116225ce0376b18fcd7e572e18cb269e97a  /var/cache/apt/archives/zlib1g_1%3a1.3.dfsg+really1.3.1-1ubuntu3_armhf.deb
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

RUST_TARGET=armv7-unknown-linux-gnueabihf
rustup target add "$RUST_TARGET"
CARGO_BUILD_TARGET=$RUST_TARGET
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
export CARGO_BUILD_TARGET CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER

# MAKE_HOST and BUILD give the bundled autotools libraries the right --host;
# TARGET tells the Makefile where cargo puts the armv7 binaries.
CROSS="MAKE_HOST=arm-linux-gnueabihf BUILD=x86_64-linux-gnu TARGET=$RUST_TARGET"

# Build ready for packaging.
./configure --prefix=/usr CC="arm-linux-gnueabihf-gcc -fdebug-prefix-map=$(pwd)=/home/clightning"
# shellcheck disable=SC2086
make -j"$MAKEPAR" PYTHON_VERSION=3 VERSION="$VERSION" $CROSS
# shellcheck disable=SC2086
make -j"$MAKEPAR" install DESTDIR=inst/ VERSION="$VERSION" $CROSS

cd inst && tar --sort=name \
      --mtime="$MTIME 00:00Z" \
      --owner=0 --group=0 --numeric-owner -cvaf ../clightning-"$VERSION-$PLATFORM-$ARCH".tar.xz .
