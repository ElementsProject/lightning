#!/bin/sh

set -e

DIRNAME="bitcoin-${BITCOIN_VERSION}"
EDIRNAME="elements-${ELEMENTS_VERSION}"
FILENAME="${DIRNAME}-x86_64-linux-gnu.tar.gz"
EFILENAME="${EDIRNAME}-x86_64-linux-gnu.tar.bz2"

cd /tmp/
wget "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${FILENAME}"
wget -q "https://storage.googleapis.com/c-lightning-tests/${EFILENAME}"
tar -xf "${FILENAME}"
tar -xaf "${EFILENAME}"
sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"


rm -rf "${FILENAME}" "${EFILENAME}" "${DIRNAME}" "${EDIRNAME}"
