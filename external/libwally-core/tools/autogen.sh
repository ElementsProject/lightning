#!/bin/sh
autoreconf --install --force --warnings=all
if uname | grep "Darwin" >/dev/null 2>&1; then
    # Hack libtool to work around OSX requiring AR set to /usr/bin/libtool
    for f in ./tools/build-aux/ltmain.sh ./src/secp256k1/build-aux/ltmain.sh; do
        for a in x t; do
             gsed -i -e "s/\$AR $a /ar $a /" $f
        done
    done
fi
