#!/bin/sh
# If an argument is specified, that dir is checked before downloading,
# and updated after successful install.

set -e

export BITCOIN_VERSION=27.1
export ELEMENTS_VERSION=23.2.1

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
    if [ -f "$1/${EFILENAME}" ]; then
	cp "$1/${EFILENAME}" .
    else
	wget "https://github.com/ElementsProject/elements/releases/download/elements-${ELEMENTS_VERSION}/${EFILENAME}"
    fi
    tar -xf "${EFILENAME}"
    [ "$1" = "" ] || cp "${EFILENAME}" "$1"/
    sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${EFILENAME}" "${EDIRNAME}"
else
    if [ -f "$1/${FILENAME}" ]; then
	cp "$1/${FILENAME}" .
    else
	wget "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${FILENAME}"
    fi
    tar -xf "${FILENAME}"
    [ "$1" = "" ] || cp "${FILENAME}" "$1"/
    sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${FILENAME}" "${DIRNAME}"
fi

