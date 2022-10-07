#! /usr/bin/env bash

# Creates wheel files
#
# The wheel file can be installed with
# pip install wallycore*.whl
#
# Like all tools/ scripts, this should be run from the project root.

set -e

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if [ ! -f "src/secp256k1/README.md" ]; then
    git submodule sync --recursive
    git submodule update --init --recursive
fi

function build_wheel {
    ./tools/cleanup.sh

    # Create a new virtualenv and use it to build the wheel using pip wheel
    virtualenv -p $1 .venv
    source .venv/bin/activate

    pip install wheel
    pip wheel --wheel-dir=./wally_dist .

    deactivate

    # Smoke test the built wheel by installing it into a new virtualenv
    virtualenv -p $1 .venv/.smoketest
    source .venv/.smoketest/bin/activate

    pip install --upgrade pip
    pip install --find-links=./wally_dist wallycore
    python -c "import wallycore as wally; assert wally.hex_from_bytes(wally.hex_to_bytes('ff')) == 'ff'"

    deactivate
    rm -rf .venv
}

mkdir -p wally_dist

PYV_LIST="python2 python3"
if [ -n "$1" ]; then
    PYV_LIST="$1"
fi

for pyv in $PYV_LIST; do
    if have_cmd $pyv; then
        build_wheel $pyv
    fi
done

./tools/cleanup.sh
