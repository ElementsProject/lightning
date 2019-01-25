#!/bin/bash -x
set -e

CWD=$(pwd)
export SLOW_MACHINE=1
export CC=${COMPILER:-gcc}
export DEVELOPER=${DEVELOPER:-1}
export SOURCE_CHECK_ONLY=${SOURCE_CHECK_ONLY:-"false"}
export COMPAT=${COMPAT:-1}
export PATH=$CWD/dependencies/bin:"$HOME"/.local/bin:"$PATH"

mkdir -p dependencies/bin || true

# Download bitcoind and bitcoin-cli 
if [ ! -f dependencies/bin/bitcoind ]; then
    wget https://bitcoin.org/bin/bitcoin-core-0.17.1/bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
    tar -xzf bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
    mv bitcoin-0.17.1/bin/* dependencies/bin
    rm -rf bitcoin-0.17.1-x86_64-linux-gnu.tar.gz bitcoin-0.17.1
fi

pyenv global 3.7
pip3 install --user --quiet -r tests/requirements.txt
pip3 install --quiet \
     pytest-test-groups==1.0.3

echo "Configuration which is going to be built:"
echo -en 'travis_fold:start:script.1\\r'
./configure CC="$CC"
cat config.vars
echo -en 'travis_fold:end:script.1\\r'

if [ "$SOURCE_CHECK_ONLY" == "false" ]; then
    echo -en 'travis_fold:start:script.2\\r'
    make -j3 > /dev/null
    echo -en 'travis_fold:end:script.2\\r'

    echo -en 'travis_fold:start:script.3\\r'
    make check
    echo -en 'travis_fold:end:script.3\\r'
else
    git clone https://github.com/lightningnetwork/lightning-rfc.git
    make check-source BOLTDIR=lightning-rfc
fi
