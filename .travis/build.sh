#!/bin/bash -x
set -e

CWD=$(pwd)
export SLOW_MACHINE=1
export CC=${COMPILER:-gcc}
export DEVELOPER=${DEVELOPER:-1}
export EXPERIMENTAL_FEATURES=${EXPERIMENTAL_FEATURES:-0}
export COMPAT=${COMPAT:-1}
export PATH=$CWD/dependencies/bin:"$HOME"/.local/bin:"$PATH"
export PYTEST_PAR=${PYTEST_PAR:-2}
export PYTEST_SENTRY_ALWAYS_REPORT=1
export BOLTDIR=lightning-rfc
export TEST_DB_PROVIDER=${DB:-"sqlite3"}
export TEST_NETWORK=${NETWORK:-"regtest"}
export PYTEST_OPTS="--reruns=2 --maxfail=5 ${PYTEST_OPTS}"

# Allow up to 4 concurrent tests when not under valgrind, which might run out of memory.
if [ "$VALGRIND" = 0 ]; then
    PYTEST_PAR=4
fi
export TEST_CMD=${TEST_CMD:-"make -j $PYTEST_PAR pytest"}

mkdir -p dependencies/bin || true

# Download bitcoind, elementsd, bitcoin-cli and elements-cli
if [ ! -f dependencies/bin/bitcoind ]; then
    wget -q https://storage.googleapis.com/c-lightning-tests/bitcoin-0.20.1-x86_64-linux-gnu.tar.bz2
    wget -q https://storage.googleapis.com/c-lightning-tests/elements-0.18.1.8-x86_64-linux-gnu.tar.bz2
    tar -xjf bitcoin-0.20.1-x86_64-linux-gnu.tar.bz2
    tar -xjf elements-0.18.1.8-x86_64-linux-gnu.tar.bz2
    mv bitcoin-0.20.1/bin/* dependencies/bin
    mv elements-0.18.1.8/bin/* dependencies/bin
    rm -rf \
       bitcoin-0.20.1-x86_64-linux-gnu.tar.gz \
       bitcoin-0.20.1 \
       elements-0.18.1.8-x86_64-linux-gnu.tar.bz2 \
       elements-0.18.1.8
fi

if [ "$NO_PYTHON" != 1 ]; then
    pyenv global 3.7

    pip3 install --user -U --quiet --progress-bar off \
	 pip \
	 pytest-test-groups==1.0.3

    pip3 install --user -U --quiet --progress-bar off \
	 -r requirements.txt \
	 -r contrib/pyln-client/requirements.txt \
	 -r contrib/pyln-proto/requirements.txt \
	 -r contrib/pyln-testing/requirements.txt

    pip3 install --user -U --quiet --progress-bar off \
	 blinker \
	 pytest-sentry \
	 pytest-rerunfailures
fi

echo "Configuration which is going to be built:"
echo -en 'travis_fold:start:script.1\\r'
./configure CC="$CC"
cat config.vars
echo -en 'travis_fold:end:script.1\\r'

git clone https://github.com/lightningnetwork/lightning-rfc.git

if [ "$TARGET_HOST" == "arm-linux-gnueabihf" ] || [ "$TARGET_HOST" == "aarch64-linux-gnu" ]
then
    export QEMU_LD_PREFIX=/usr/"$TARGET_HOST"/
    export MAKE_HOST="$TARGET_HOST"
    export BUILD=x86_64-pc-linux-gnu
    export AR="$TARGET_HOST"-ar
    export AS="$TARGET_HOST"-as
    export CC="$TARGET_HOST"-gcc
    export CXX="$TARGET_HOST"-g++
    export LD="$TARGET_HOST"-ld
    export STRIP="$TARGET_HOST"-strip
    export CONFIGURATION_WRAPPER=qemu-"${TARGET_HOST%%-*}"-static

    wget -q https://zlib.net/zlib-1.2.11.tar.gz \
    && tar xf zlib-1.2.11.tar.gz \
    && cd zlib-1.2.11 \
    && ./configure --prefix="$QEMU_LD_PREFIX" \
    && make \
    && sudo make install
    cd .. && rm zlib-1.2.11.tar.gz && rm -rf zlib-1.2.11

    wget -q https://www.sqlite.org/2018/sqlite-src-3260000.zip \
    && unzip -q sqlite-src-3260000.zip \
    && cd sqlite-src-3260000 \
    && automake --add-missing --force-missing --copy || true \
    && ./configure --disable-tcl --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host="$TARGET_HOST" --prefix="$QEMU_LD_PREFIX" \
    && make \
    && sudo make install
    cd .. && rm sqlite-src-3260000.zip && rm -rf sqlite-src-3260000

    wget -q https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz \
    && tar xf gmp-6.1.2.tar.xz \
    && cd gmp-6.1.2 \
    && ./configure --disable-assembly --prefix="$QEMU_LD_PREFIX" --host="$TARGET_HOST" \
    && make \
    && sudo make install
    cd .. && rm gmp-6.1.2.tar.xz && rm -rf gmp-6.1.2

    ./configure --enable-static

    echo -en 'travis_fold:start:script.2\\r'
    make -j3 > /dev/null
    echo -en 'travis_fold:end:script.2\\r'

    # Tests would need to be wrapped with qemu-<arch>-static
    #echo -en 'travis_fold:start:script.3\\r'
    #make -j$PYTEST_PAR check-units
    #echo -en 'travis_fold:end:script.3\\r'
else
    echo -en 'travis_fold:start:script.2\\r'
    make -j8
    echo -en 'travis_fold:end:script.2\\r'

    echo -en 'travis_fold:start:script.3\\r'
    $TEST_CMD
    echo -en 'travis_fold:end:script.3\\r'
fi
