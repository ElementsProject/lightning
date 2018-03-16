Library Requirements
--------------------

You will need several development libraries:
* libsqlite3: for database support.
* libgmp: for secp256k1

For actually doing development and running the tests, you will also need:
* pip3: to install python-bitcoinlib
* asciidoc: for formatting the man pages (if you change them)
* valgrind: for extra debugging checks

You will also need a version of bitcoind with segregated witness and
estimatesmartfee economical node, such as the 0.15 or above.

To Build on Ubuntu 15.10 or above
---------------------

Get dependencies:

    sudo apt-get install -y \
      autoconf automake build-essential git libtool libgmp-dev \
      libsqlite3-dev python python3 net-tools libsodium-dev

If you don't have Bitcoin installed locally you'll need to install that
as well:

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install -y bitcoind

For development or running tests, get additional dependencies:

    sudo apt-get install -y asciidoc valgrind python3-pip
    sudo pip3 install python-bitcoinlib

Clone lightning:

    git clone https://github.com/ElementsProject/lightning.git
    cd lightning

Build lightning:

    make

Running lightning:

    bitcoind &
    ./lightningd/lightningd &
    ./cli/lightning-cli help

**Note**: You may need to include `testnet=1` in `bitcoin.conf`

To Build on FreeBSD 11.1-RELEASE
---------------------

Get dependencies:

    # pkg install -y \
      autoconf automake git gmake libtool python python3 sqlite3

If you don't have Bitcoin installed locally you'll need to install that
as well:

    # pkg install -y bitcoin-daemon bitcoin-utils

Clone lightning:

    $ git clone https://github.com/ElementsProject/lightning.git
    $ cd lightning

Build lightning:

    $ gmake

Running lightning:

**Note**: Edit your `/usr/local/etc/bitcoin.conf` to include
`rpcuser=<foo>` and `rpcpassword=<bar>` first, you may also need to
include `testnet=1`

    # service bitcoind start
    $ ./lightningd/lightningd &
    $ ./cli/lightning-cli help

To Build on Nix{,OS}
--------------------

Untested on MacOS/Windows/Other Linux. Works on NixOS.

Use nix-shell launch a shell with a full clightning dev environment:

```
$ nix-shell -Q -p gdb sqlite autoconf git clang libtool gmp sqlite autoconf \
autogen automake 'python3.withPackages (p: [p.bitcoinlib])' \
valgrind asciidoc --run make
```
To Build on Mac
---------------------

Assume you have Xcode and HomeBrew installed on your Mac.
Get dependencies:

    $ brew install autoconf automake libtool python3 gmp libsodium gnu-sed

If you don't have bitcoind installed locally you'll need to install that
as well:

    $ brew install \
    berkeley-db4 boost miniupnpc openssl pkg-config protobuf qt libevent
    $ git clone https://github.com/bitcoin/bitcoin
    $ cd bitcoin
    $ ./autogen.sh
    $ ./configure
    $ make & make install

Clone lightning:

    $ git clone https://github.com/ElementsProject/lightning.git
    $ cd lightning

Build lightning:

    $ make

Running lightning:

**Note**: Edit your `~/Library/Application\ Support/Bitcoin/bitcoin.conf`
to include `rpcuser=<foo>` and `rpcpassword=<bar>` first, you may also
need to include `testnet=1`

    bitcoind &
    ./lightningd/lightningd &
    ./cli/lightning-cli help
To cross-compile for Android
--------------------

Make a standalone toolchain as per
https://developer.android.com/ndk/guides/standalone_toolchain.html.
For c-lightning you must target an API level of 24 or higher.

Depending on your toolchain location and target arch, source env variables
such as:

    export PATH=$PATH:/path/to/android/toolchain/bin
    # Change next line depending on target device arch
    target_host=arm-linux-androideabi
    export AR=$target_host-ar
    export AS=$target_host-clang
    export CC=$target_host-clang
    export CXX=$target_host-clang++
    export LD=$target_host-ld
    export STRIP=$target_host-strip

Two makefile targets should not be cross-compiled so we specify a native CC:

    make CC=clang clean ccan/tools/configurator/configurator
    make clean -C ccan/ccan/cdump/tools \
      && make CC=clang -C ccan/ccan/cdump/tools

Install the `qemu-user` package.
This will allow you to properly configure
the build for the target device environment.
Build with:

    BUILD=x86_64 HOST=arm-linux-androideabi \
      make PIE=1 DEVELOPER=0 \
      CONFIGURATOR_CC="arm-linux-androideabi-clang -static"
