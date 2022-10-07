#! /usr/bin/env bash

set -e

ENABLE_ELEMENTS=""
if [ "$1" = "--enable-elements" ]; then
    ENABLE_ELEMENTS="$1"
fi

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi

$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh

# Note: This doesn't work yet, see https://github.com/emscripten-core/emscripten/issues/6233
# we pass --enable-export-all to prevent library symbols from being hidden,
# the wasm build then makes visible only the functions marked EMSCRIPTEN_KEEPALIVE.
#trap "sed -i 's/EMSCRIPTEN_KEEPALIVE/WALLY_CORE_API/g' include/*.h src/*.h" ERR EXIT
#sed -i 's/WALLY_CORE_API/EMSCRIPTEN_KEEPALIVE/g' include/*.h src/*.h

export CFLAGS="-fno-stack-protector"
emconfigure ./configure --build=$HOST_OS ac_cv_c_bigendian=no --disable-swig-python --disable-swig-java $ENABLE_ELEMENTS --disable-ecmult-static-precomputation --disable-tests --enable-export-all
emmake make -j $num_jobs

: ${OPTIMIZATION_LEVEL:=3}
: ${EXTRA_EXPORTED_RUNTIME_METHODS:="['getValue', 'UTF8ToString', 'ccall']"}
# Get the list of functions to export
source ./tools/wasm_exports.sh

mkdir -p wally_dist

emcc -O$OPTIMIZATION_LEVEL \
    -s "EXTRA_EXPORTED_RUNTIME_METHODS=$EXTRA_EXPORTED_RUNTIME_METHODS" \
    -s "EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS" \
    -s FILESYSTEM=0 \
    $EMCC_OPTIONS \
    ./src/.libs/*.o src/secp256k1/src/*.o src/ccan/ccan/*/.libs/*.o src/ccan/ccan/*/*/.libs/*.o \
    -o wally_dist/wallycore.html \
    --shell-file contrib/shell_minimal.html
