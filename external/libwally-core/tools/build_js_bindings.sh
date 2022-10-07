#! /usr/bin/env bash

set -e

if [ ! -f "src/secp256k1/README.md" ]; then
    git submodule sync --recursive
    git submodule update --init --recursive
fi

tools/cleanup.sh
tools/autogen.sh
PYTHON_VERSION=`python3 --version | cut -d ' ' -f 2 | cut -d '.' -f -2` ./configure --enable-debug --enable-js-wrappers --disable-swig-python --disable-swig-java --enable-ecmult-static-precomputation --enable-elements $WALLY_CONFIGURE
num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi
make -o configure clean
make -o configure -j $num_jobs
make -o configure check

./tools/cleanup.sh
