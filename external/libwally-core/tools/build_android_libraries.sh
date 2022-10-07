#! /usr/bin/env bash
#
# Build native android libraries with JNI bindings, for use with C or Java.
# Requires JAVA_HOME and ANDROID_NDK to be set.
#
set -e

if [ ! -f "src/secp256k1/README.md" ]; then
    git submodule sync --recursive
    git submodule update --init --recursive
fi

if [ -z "$ANDROID_NDK" ]; then
    export ANDROID_NDK=$(dirname `which ndk-build 2>/dev/null`)
fi
echo ${ANDROID_NDK:?}
if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME=$JAVA7_HOME
fi
echo ${JAVA_HOME:?}

source $PWD/tools/android_helpers.sh

$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh

# Build everything unless the user passed a single target name
ARCH_LIST=$(android_get_arch_list)
if [ -n "$1" ]; then
    ARCH_LIST="$1"
fi

for arch in $ARCH_LIST; do
    # Use API level 19 for non-64 bit targets for better device coverage
    api="19"
    if [[ $arch == *"64"* ]]; then
        api="21"
    fi

    # Location of the NDK tools to build with
    toolsdir=$(android_get_build_tools_dir)

    # Extra configure options
    useropts=""

    # Configure and build with the above options
    android_build_wally $arch $toolsdir $api $useropts

    # Copy and strip the build result
    mkdir -p $PWD/release/lib/$arch
    STRIP_TOOL=$(android_get_build_tool $arch $toolsdir $api "strip")
    $STRIP_TOOL -o $PWD/release/lib/$arch/libwallycore.so $PWD/src/.libs/libwallycore.so
done

# Copy headers and Java wrapper
# The andoid release files can be used from Java or in native code
mkdir -p $PWD/release/include $PWD/release/src/swig_java/src/com/blockstream/libwally
cp $PWD/include/*.h $PWD/release/include
cp $PWD/src/swig_java/src/com/blockstream/libwally/Wally.java $PWD/release/src/swig_java/src/com/blockstream/libwally
