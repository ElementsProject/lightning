Install
=======

1. [Library Requirements](#library-requirements)
2. [Ubuntu](#to-build-on-ubuntu)
3. [Fedora](#to-build-on-fedora)
4. [FreeBSD](#to-build-on-freebsd)
5. [NixOS](#to-build-on-nixos)
6. [macOS](#to-build-on-macos)
7. [Android](#to-cross-compile-for-android)
8. [Raspberry Pi](#to-cross-compile-for-raspberry-pi)
9. [Armbian](#to-compile-for-armbian)
10. [Additional steps](#additional-steps)

Library Requirements
--------------------

You will need several development libraries:
* libsqlite3: for database support.
* libgmp: for secp256k1
* zlib: for compression routines.

For actually doing development and running the tests, you will also need:
* pip3: to install python-bitcoinlib
* asciidoc: for formatting the man pages (if you change them)
* valgrind: for extra debugging checks

You will also need a version of bitcoind with segregated witness and
estimatesmartfee economical node, such as the 0.15 or above.

To Build on Ubuntu
---------------------

OS version: Ubuntu 15.10 or above

Get dependencies:

    sudo apt-get update
    sudo apt-get install -y \
      autoconf automake build-essential git libtool libgmp-dev \
      libsqlite3-dev python python3 net-tools zlib1g-dev libsodium \
	  libbase58-dev

If you don't have Bitcoin installed locally you'll need to install that
as well:

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install -y bitcoind

For development or running tests, get additional dependencies:

    sudo apt-get install -y asciidoc valgrind python3-pip
    sudo pip3 install -r tests/requirements.txt

Clone lightning:

    git clone https://github.com/ElementsProject/lightning.git
    cd lightning

Build lightning:

    ./configure
    make

Running lightning:

    bitcoind &
    ./lightningd/lightningd &
    ./cli/lightning-cli help

**Note**: You may need to include `testnet=1` in `bitcoin.conf`

To Build on Fedora
---------------------

OS version: Fedora 27 or above

Get dependencies:
```
$ sudo dnf update -y && \
        sudo dnf groupinstall -y \
                'C Development Tools and Libraries' \
                'Development Tools' && \
        sudo dnf install -y \
                asciidoc \
                clang \
                gmp-devel \
                libsq3-devel \
                python2-devel \
                python3-devel \
                python3-pip \
                python3-setuptools \
                net-tools \
                net-tools \
                valgrind \
                wget \
                zlib-devel \
				libsodium-devel && \
        sudo dnf clean all
```

Make sure you have [bitcoind](https://github.com/bitcoin/bitcoin) available to run

Clone lightning:
```
$ git clone https://github.com/ElementsProject/lightning.git
$ cd lightning
```

Build and install lightning:
```
$lightning> ./configure
$lightning> make
$lightning> sudo make install
```

Running lightning (mainnet):
```
$ bitcoind &
$ lightningd --network=bitcoin
```

Running lightning on testnet:
```
$ bitcoind -testnet &
$ lightningd --network=testnet
```

To Build on FreeBSD
---------------------

OS version: FreeBSD 11.1-RELEASE or above

Get dependencies:

    # pkg install -y \
      autoconf automake git gmp asciidoc gmake libtool python python3 sqlite3 libsodium

If you don't have Bitcoin installed locally you'll need to install that
as well:

    # pkg install -y bitcoin-daemon bitcoin-utils

Clone lightning:

    $ git clone https://github.com/ElementsProject/lightning.git
    $ cd lightning

Build lightning:

    $ ./configure
    $ gmake
    $ gmake install

Running lightning:

**Note**: Edit your `/usr/local/etc/bitcoin.conf` to include
`rpcuser=<foo>` and `rpcpassword=<bar>` first, you may also need to
include `testnet=1`

    # service bitcoind start
    $ ./lightningd/lightningd &
    $ ./cli/lightning-cli help

To Build on NixOS
--------------------

Use nix-shell launch a shell with a full clightning dev environment:

```
$ nix-shell -Q -p gdb sqlite autoconf git clang libtool gmp sqlite autoconf \
autogen automake libsodium 'python3.withPackages (p: [p.bitcoinlib])' \
valgrind asciidoc --run make
```

To Build on macOS
---------------------

Assuming you have Xcode and Homebrew installed. Install dependencies:

    $ brew install autoconf automake libtool python3 gmp gnu-sed

If you don't have bitcoind installed locally you'll need to install that
as well:

    $ brew install berkeley-db4 boost miniupnpc openssl pkg-config libevent libsodium
    $ git clone https://github.com/bitcoin/bitcoin
    $ cd bitcoin
    $ ./autogen.sh
    $ ./configure
    $ make src/bitcoind src/bitcoin-cli && make install

Clone lightning:

    $ git clone https://github.com/ElementsProject/lightning.git
    $ cd lightning

Build lightning:

    $ ./configure
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

    BUILD=x86_64 MAKE_HOST=arm-linux-androideabi \
      make PIE=1 DEVELOPER=0 \
      CONFIGURATOR_CC="arm-linux-androideabi-clang -static"

To cross-compile for Raspberry Pi
--------------------

Obtain the [official Raspberry Pi toolchains](https://github.com/raspberrypi/tools).
This document assumes compilation will occur towards the Raspberry Pi 3 
(arm-linux-gnueabihf as of Mar. 2018).

Depending on your toolchain location and target arch, source env variables
will need to be set. They can be set from the command line as such:

    export PATH=$PATH:/path/to/arm-linux-gnueabihf/bin
    # Change next line depending on specific Raspberry Pi device
    target_host=arm-linux-gnueabihf
    export AR=$target_host-ar
    export AS=$target_host-as
    export CC=$target_host-gcc
    export CXX=$target_host-g++
    export LD=$target_host-ld
    export STRIP=$target_host-strip

Install the `qemu-user` package. This will allow you to properly configure the
build for the target device environment.
Config the arm elf interpreter prefix:

    export QEMU_LD_PREFIX=/path/to/raspberry/arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf/arm-linux-gnueabihf/sysroot/

Obtain and install cross-compiled versions of sqlite3, gmp and zlib:

Download and build zlib:

    wget https://zlib.net/zlib-1.2.11.tar.gz
    tar xvf zlib-1.2.11.tar.gz
    cd zlib-1.2.11
    ./configure --prefix=$QEMU_LD_PREFIX
    make
    make install

Download and build sqlite3:

    wget https://www.sqlite.org/2018/sqlite-src-3260000.zip
    unzip sqlite-src-3260000.zip
    cd sqlite-src-3260000
    ./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host=$target_host --prefix=$QEMU_LD_PREFIX
    make
    make install

Download and build gmp:

    wget https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz
    tar xvf gmp-6.1.2.tar.xz 
    cd gmp-6.1.2
    ./configure --disable-assembly --prefix=$QEMU_LD_PREFIX
    make
    make install

Then, build c-lightning with the following commands:

    ./configure
    make

To compile for Armbian
--------------------
For all the other Pi devices out there, consider using [Armbian](https://www.armbian.com).

You can compile in `customize-image.sh` using the instructions for Ubuntu.

A working example that compiles both bitcoind and c-lightning for Armbian can
be found [here](https://github.com/Sjors/armbian-bitcoin-core).

Additional steps
--------------------
Go to [README](https://github.com/ElementsProject/lightning/blob/master/README.md) for more information how to create an address, add funds, connect to a node, etc.
