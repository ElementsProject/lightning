#!/bin/sh

set -e

DIRNAME="bitcoin-${BITCOIN_VERSION}"
EDIRNAME="elements-${ELEMENTS_VERSION}"
FILENAME="${DIRNAME}-x86_64-linux-gnu.tar.gz"
EFILENAME="${EDIRNAME}-x86_64-linux-gnu.tar.gz"

cd /tmp/
wget "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${FILENAME}"
wget "https://github.com/ElementsProject/elements/releases/download/elements-${ELEMENTS_VERSION}/${EFILENAME}"
tar -xf "${FILENAME}"
tar -xf "${EFILENAME}"
sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"


rm -rf "${FILENAME}" "${EFILENAME}" "${DIRNAME}" "${EDIRNAME}"
