#!/bin/bash

# Creates tarballs with a binary egg file and setup.py for python2/3.
# After unpacking, the resulting egg file can be installed with
# python setup.py easy_install wallycore*.egg
# Like all tools/ scripts, this should be run from the project root.

PLATFORM=$(python -c 'import platform; print(platform.system().lower())')
BITS=$(python -c 'import sys; print("64" if sys.maxsize > 2**32 else "32")')
MACHINE=$(python -c 'import platform; print(platform.machine().lower())')
NAME="wallycore-$PLATFORM-$MACHINE-$BITS"

function build {
    ./tools/cleanup.sh
    virtualenv -p $1 .venv
    source .venv/bin/activate
    PYTHONDONTWRITEBYTECODE= $1 setup.py install
    cp setup.py dist
    mv dist $NAME-$1
    tar czf $NAME-$1.tar.gz $NAME-$1
    sha256sum $NAME-$1.tar.gz >$NAME-$1.tar.gz.sha256
    #gpg --armor --output $NAME-$1.tar.gz.asc --detach-sign $NAME-$1.tar.gz
    rm -r $NAME-$1
    deactivate
}

build python2
build python3

./tools/cleanup.sh

