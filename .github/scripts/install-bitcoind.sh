#!/bin/sh

set -e

DIRNAME="bitcoin-${BITCOIN_VERSION}"
EDIRNAME="elements-${ELEMENTS_VERSION}"
FILENAME="${DIRNAME}-x86_64-linux-gnu.tar.bz2"
EFILENAME="${EDIRNAME}-x86_64-linux-gnu.tar.bz2"

cd /tmp/
wget "https://storage.googleapis.com/c-lightning-tests/$FILENAME"
wget -q "https://storage.googleapis.com/c-lightning-tests/${EFILENAME}"
tar -xaf "${FILENAME}"
tar -xaf "${EFILENAME}"
sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"


rm -rf "${FILENAME}" "${EFILENAME}" "${DIRNAME}" "${EDIRNAME}"
