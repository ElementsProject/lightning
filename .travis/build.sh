#!/bin/bash -x
set -e

CWD=$(pwd)
export SLOW_MACHINE=1
export CC=${COMPILER:-gcc}
export DEVELOPER=${DEVELOPER:-1}
export EXPERIMENTAL_FEATURES=${EXPERIMENTAL_FEATURES:-0}
export SOURCE_CHECK_ONLY=${SOURCE_CHECK_ONLY:-"false"}
export COMPAT=${COMPAT:-1}
export PATH=$CWD/dependencies/bin:"$HOME"/.local/bin:"$PATH"
export PYTEST_PAR=2

# If we're not in developer mode, tests spend a lot of time waiting for gossip!
# But if we're under valgrind, we can run out of memory!
if [ "$DEVELOPER" = 0 ] && [ "$VALGRIND" = 0 ]; then
    PYTEST_PAR=4
fi

mkdir -p dependencies/bin || true

# Download bitcoind and bitcoin-cli 
if [ ! -f dependencies/bin/bitcoind ]; then
    wget https://bitcoin.org/bin/bitcoin-core-0.18.1/bitcoin-0.18.1-x86_64-linux-gnu.tar.gz
    tar -xzf bitcoin-0.18.1-x86_64-linux-gnu.tar.gz
    mv bitcoin-0.18.1/bin/* dependencies/bin
    rm -rf bitcoin-0.18.1-x86_64-linux-gnu.tar.gz bitcoin-0.18.1
fi

pyenv global 3.7
pip3 install --user --quiet -r requirements.txt -r tests/requirements.txt -r doc/requirements.txt
pip3 install --quiet \
     pytest-test-groups==1.0.3

echo "Configuration which is going to be built:"
echo -en 'travis_fold:start:script.1\\r'
./configure CC="$CC"
cat config.vars
echo -en 'travis_fold:end:script.1\\r'

cat > pytest.ini << EOF
[pytest]
addopts=-p no:logging --color=no --force-flaky
EOF

if [ "$TARGET_HOST" == "arm-linux-gnueabihf" ] || [ "$TARGET_HOST" == "arm-linux-gnueabihf" ]
then
    export QEMU_LD_PREFIX=/usr/"$TARGET_HOST"/
    export MAKE_HOST="$TARGET_HOST"
    export AR="$TARGET_HOST"-ar
    export AS="$TARGET_HOST"-as
    export CC="$TARGET_HOST"-gcc
    export CXX="$TARGET_HOST"-g++
    export LD="$TARGET_HOST"-ld
    export STRIP="$TARGET_HOST"-strip

    wget -q https://zlib.net/zlib-1.2.11.tar.gz \
    && tar xvf zlib-1.2.11.tar.gz \
    && cd zlib-1.2.11 \
    && ./configure --prefix="$QEMU_LD_PREFIX" \
    && make \
    && sudo make install 
    cd .. && rm zlib-1.2.11.tar.gz && rm -rf zlib-1.2.11

    wget -q https://www.sqlite.org/2018/sqlite-src-3260000.zip \
    && unzip sqlite-src-3260000.zip \
    && cd sqlite-src-3260000 \
    && ./configure --disable-tcl --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host="$TARGET_HOST" --prefix="$QEMU_LD_PREFIX" \
    && make \
    && sudo make install 
    cd .. && rm sqlite-src-3260000.zip && rm -rf sqlite-src-3260000

    wget -q https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz \
    && tar xvf gmp-6.1.2.tar.xz \
    && cd gmp-6.1.2 \
    && ./configure --disable-assembly --prefix="$QEMU_LD_PREFIX" --host="$TARGET_HOST" \
    && make \
    && sudo make install 
    cd .. && rm gmp-6.1.2.tar.xz && rm -rf gmp-6.1.2

    ./configure --enable-static

    echo -en 'travis_fold:start:script.2\\r'
    make -j3 > /dev/null
    echo -en 'travis_fold:end:script.2\\r'

    echo -en 'travis_fold:start:script.3\\r'
    make -j$PYTEST_PAR check-units
    echo -en 'travis_fold:end:script.3\\r'
elif [ "$SOURCE_CHECK_ONLY" == "false" ]; then
    echo -en 'travis_fold:start:script.2\\r'
    make -j3 > /dev/null
    echo -en 'travis_fold:end:script.2\\r'

    echo -en 'travis_fold:start:script.3\\r'
    make -j$PYTEST_PAR check
    echo -en 'travis_fold:end:script.3\\r'
else
    git clone https://github.com/lightningnetwork/lightning-rfc.git
    echo -en 'travis_fold:start:script.2\\r'
    make -j3 > /dev/null
    echo -en 'travis_fold:end:script.2\\r'
    make check-source BOLTDIR=lightning-rfc
fi
