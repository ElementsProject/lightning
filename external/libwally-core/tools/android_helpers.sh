# Source this file from your build scripts to use the functions provided

# List the android architectures supported by wally
function android_get_arch_list() {
    echo "armeabi-v7a arm64-v8a x86 x86_64"
}


# Get the location of the android NDK build tools to build with
function android_get_build_tools_dir() {
    if [ "$(uname)" == "Darwin" ]; then
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64
    else
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64
    fi
}


# Get the full path to a given build tool
# arch: An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
# tool: The tool to get (clang,ld,strip,ar,nm etc)
function android_get_build_tool() {
    local arch=$1 toolsdir=$2 api=$3 tool=$4
    case $arch in
        arm64-v8a) tool_arch=aarch64;;
        armeabi-v7a)
           if [ "$tool" == "clang" ]; then
               tool_arch=armv7a
            else
               tool_arch=arm
            fi
            ;;
        x86) tool_arch=i686;;
        *) tool_arch=$arch;;
    esac
    if [ "$tool" == "clang" ]; then
        api_prefix="$api"
    else
        api_prefix=""
    fi
     full_path="$toolsdir/bin/$tool_arch-linux-android*$api_prefix-$tool"
    if [ -x $full_path ]; then
        echo $full_path
    else
        echo "ERROR: Failed to find tool $full_path" >&2
        exit 1
    fi
}


# Get the compiler flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
function android_get_cflags() {
    local arch=$1 toolsdir=$2
    local cflags="$CFLAGS -isystem $toolsdir/sysroot/include"
    case $arch in
       armeabi-v7a) cflags="$cflags -march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb";;
       arm64-v8a) cflags="$cflags -flax-vector-conversions";;
    esac
    echo $cflags
}


# Get the configure flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# useropts: The users configure options e.g. --enable-swig-java
function android_get_configure_flags() {
    local arch=$1 toolsdir=$2 archfilename=$1
    shift 2
    local useropts=$*
    case $arch in
        armeabi-v7a) archfilename=arm;;
        arm64-v8a) archfilename=aarch64;;
    esac

    local strip_tool=$(android_get_build_tool $arch $toolsdir "unused" "strip")
    local host=$(basename $strip_tool | sed 's/-strip$//')
    local args="--host=$host --enable-swig-java --disable-swig-python \
--enable-elements --enable-endomorphism --enable-ecmult-static-precomputation"
    case $arch in
       arm*) args="$args --with-asm=auto";;
       x86_64) args="$args --with-asm=x86_64";;
    esac
    echo "$args $useropts"
}

# Create a toolchain configure and build wally for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
# useropts: The users configure options e.g. --enable-swig-java
function android_build_wally() {
    local arch=$1 toolsdir=$2 api=$3
    shift 3
    local useropts=$*

    CC=$(android_get_build_tool $arch $toolsdir $api "clang") \
        CFLAGS=$(android_get_cflags $arch $toolsdir) \
        PATH="$toolsdir/bin:$PATH" \
        ./configure $(android_get_configure_flags $arch $toolsdir $useropts)
    local num_jobs=4
    if [ -f /proc/cpuinfo ]; then
        num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
    fi
    PATH="$toolsdir/bin:$PATH" make -o configure clean
    PATH="$toolsdir/bin:$PATH" make -o configure -j $num_jobs
}
