#! /usr/bin/env bash

# Creates manylinux compatible python wheels.
#
# Like all tools/ scripts, this should be run from the project root.

set -e

if [ ! -d "/opt/python" ]; then
    echo "No python binaries found under /opt/python/. Exiting..."
    exit 0
fi

if [ ! -f "src/secp256k1/README.md" ]; then
    git submodule sync --recursive
    git submodule update --init --recursive
fi

source ./tools/build_python_wheels.sh " "

# Remember the unmodified PATH so we can reset inbetween builds
PPATH=$PATH
for PYBIN in /opt/python/*/bin/; do
    # cp35 is deprecated in Jan 2021
    if [[ "$PYBIN" != "/opt/python/cp35-cp35m/bin/" ]]; then
        PATH=$PYBIN:$PPATH
        pip install virtualenv
        build_wheel python
        PATH=$PPATH
    fi
done

# name required by pip twine upload
for f in wally_dist/*.whl; do
    mv -- "$f" "${f/-linux_/-manylinux2014_}"
done

./tools/cleanup.sh
