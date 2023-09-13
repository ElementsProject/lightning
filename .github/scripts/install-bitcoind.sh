#!/bin/sh

set -e

DIRNAME="bitcoin-${BITCOIN_VERSION}"
EDIRNAME="elements-${ELEMENTS_VERSION}"
FILENAME="${DIRNAME}-x86_64-linux-gnu.tar.gz"
EFILENAME="${EDIRNAME}-x86_64-linux-gnu.tar.gz"

cd /tmp/

# Since we inadvertently broke `elementsd` support in the past we only
# want to download and enable the daemon that is actually going to be
# used when running in CI. Otherwise we could end up accidentally
# testing against `bitcoind` but still believe that we ran against
# `elementsd`.
if [ "$TEST_NETWORK" = "liquid-regtest" ]; then
    wget "https://github.com/ElementsProject/elements/releases/download/elements-${ELEMENTS_VERSION}/${EFILENAME}"
    tar -xf "${EFILENAME}"
    sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${EFILENAME}" "${EDIRNAME}"
else
    wget "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${FILENAME}"
    tar -xf "${FILENAME}"
    sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${FILENAME}" "${DIRNAME}"
fi

