Install
=======

- [Library Requirements](#library-requirements)
- [Ubuntu](#to-build-on-ubuntu)
- [Fedora](#to-build-on-fedora)
- [FreeBSD](#to-build-on-freebsd)
- [OpenBSD](#to-build-on-openbsd)
- [NixOS](#to-build-on-nixos)
- [macOS](#to-build-on-macos)
- [Arch Linux](#to-build-on-arch-linux)
- [Android](#to-cross-compile-for-android)
- [Raspberry Pi](#to-cross-compile-for-raspberry-pi)
- [Armbian](#to-compile-for-armbian)
- [Alpine](#to-compile-for-alpine)
- [Additional steps](#additional-steps)

Library Requirements
--------------------

You will need several development libraries:
* libsqlite3: for database support.
* libgmp: for secp256k1
* zlib: for compression routines.

For actually doing development and running the tests, you will also need:
* pip3: to install python-bitcoinlib
* valgrind: for extra debugging checks

You will also need a version of bitcoind with segregated witness and `estimatesmartfee` with `ECONOMICAL` mode support, such as the 0.16 or above.

To Build on Ubuntu
---------------------

OS version: Ubuntu 15.10 or above

Get dependencies:

    sudo apt-get update
    sudo apt-get install -y \
      autoconf automake build-essential git libtool libgmp-dev libsqlite3-dev \
      python3 python3-pip net-tools zlib1g-dev libsodium-dev gettext
    pip3 install --upgrade pip
    pip3 install --user poetry

If you don't have Bitcoin installed locally you'll need to install that
as well. It's now available via [snapd](https://snapcraft.io/bitcoin-core).

    sudo apt-get install snapd
    sudo snap install bitcoin-core
    # Snap does some weird things with binary names; you'll
    # want to add a link to them so everything works as expected
    sudo ln -s /snap/bitcoin-core/current/bin/bitcoin{d,-cli} /usr/local/bin/

Clone lightning:

    git clone https://github.com/ElementsProject/lightning.git
    cd lightning

Checkout a release tag:

    git checkout v0.11.2

For development or running tests, get additional dependencies:

    sudo apt-get install -y valgrind libpq-dev shellcheck cppcheck \
      libsecp256k1-dev jq lowdown

If you can't install `lowdown`, a version will be built in-tree.

If you want to build the Rust plugins (currently, cln-grpc):

	sudo apt-get install -y cargo rustfmt

There are two ways to build core lightning, and this depends on how you want use it.

To build cln to just install a tagged or master version you can use the following commands:

    pip3 install --upgrade pip
    pip3 install mako
    ./configure
    make
    sudo make install

N.B: if you want disable Rust because you do not want use it or simple you do not want the grpc-plugin, you can use `./configure --disable-rust`.

To build core lightning for development purpose you can use the following commands:

    pip3 install poetry
    poetry shell

This will put you in a new shell to enter the following commands:

    poetry install
    ./configure --enable-developer
    make
    make check VALGRIND=0

optionally, add `-j$(nproc)` after `make` to speed up compilation. (e.g. `make -j$(nproc)`)

Running lightning:

    bitcoind &
    ./lightningd/lightningd &
    ./cli/lightning-cli help

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
                clang \
                gettext \
                git \
                gmp-devel \
                libsq3-devel \
                python3-devel \
                python3-pip \
                python3-setuptools \
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

Checkout a release tag:
```
$ git checkout v0.11.2
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
-------------------

OS version: FreeBSD 11.1-RELEASE or above

Core Lightning is in the FreeBSD ports, so install it as any other port
(dependencies are handled automatically):

    # pkg install c-lightning

for a binary, pre-compiled package. If you want to compile locally and
fiddle with compile time options:

    # cd /usr/ports/net-p2p/c-lightning && make install

See `/usr/ports/net-p2p/c-lightning/Makefile` for instructions on how to
build from an arbitrary git commit, instead of the latest release tag.

**Note**: Make sure you've set an utf-8 locale, e.g.
`export LC_CTYPE=en_US.UTF-8`, otherwise manpage installation may fail.

Running lightning:

Configure bitcoind, if not already: add `rpcuser=<foo>` and `rpcpassword=<bar>`
to `/usr/local/etc/bitcoin.conf`, maybe also `testnet=1`.

Configure lightningd: copy `/usr/local/etc/lightningd-bitcoin.conf.sample` to
`/usr/local/etc/lightningd-bitcoin.conf` and edit according to your needs.

    # service bitcoind start
    # service lightningd start
    # lightning-cli --rpc-file /var/db/c-lightning/bitcoin/lightning-rpc --lightning-dir=/var/db/c-lightning help

To Build on OpenBSD
--------------------

OS version: OpenBSD 6.7

Install dependencies:
```
pkg_add git python gmake py3-pip libtool gmp
pkg_add automake # (select highest version, automake1.16.2 at time of writing)
pkg_add autoconf # (select highest version, autoconf-2.69p2 at time of writing)
```
Install `mako` otherwise we run into build errors:
```
pip3.7 install --user poetry
poetry install
```

Add `/home/<username>/.local/bin` to your path:

`export PATH=$PATH:/home/<username>/.local/bin`

Needed for `configure`:
```
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.16
./configure
```

Finally, build `c-lightning`:

`gmake`


To Build on NixOS
--------------------

Use nix-shell launch a shell with a full clightning dev environment:

```
$ nix-shell -Q -p gdb sqlite autoconf git clang libtool gmp sqlite autoconf \
autogen automake libsodium 'python3.withPackages (p: [p.bitcoinlib])' \
valgrind --run make
```

To Build on macOS
---------------------

Assuming you have Xcode and Homebrew installed. Install dependencies:

    $ brew install autoconf automake libtool python3 gmp gnu-sed gettext libsodium
    $ ln -s /usr/local/Cellar/gettext/0.20.1/bin/xgettext /usr/local/opt
    $ export PATH="/usr/local/opt:$PATH"

If you need SQLite (or get a SQLite mismatch build error):

    $ brew install sqlite
    $ export LDFLAGS="-L/usr/local/opt/sqlite/lib"
    $ export CPPFLAGS="-I/usr/local/opt/sqlite/include"

Some library paths are different when using `homebrew` with M1 macs, therefore the following two variables need to be set for M1 machines

    $ export CPATH=/opt/homebrew/include
    $ export LIBRARY_PATH=/opt/homebrew/lib

If you need Python 3.x for mako (or get a mako build error):

    $ brew install pyenv
    $ echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.bash_profile
    $ source ~/.bash_profile
    $ pyenv install 3.7.4
    $ pip install --upgrade pip
    $ pip install poetry

If you don't have bitcoind installed locally you'll need to install that
as well:

    $ brew install berkeley-db4 boost miniupnpc pkg-config libevent
    $ git clone https://github.com/bitcoin/bitcoin
    $ cd bitcoin
    $ ./autogen.sh
    $ ./configure
    $ make src/bitcoind src/bitcoin-cli && make install

Clone lightning:

    $ git clone https://github.com/ElementsProject/lightning.git
    $ cd lightning

Checkout a release tag:

    $ git checkout v0.11.2

Build lightning:

    $ poetry install
    $ ./configure
    $ poetry run make

Running lightning:

**Note**: Edit your `~/Library/Application\ Support/Bitcoin/bitcoin.conf`
to include `rpcuser=<foo>` and `rpcpassword=<bar>` first, you may also
need to include `testnet=1`

    bitcoind &
    ./lightningd/lightningd &
    ./cli/lightning-cli help

To Build on Arch Linux
---------------------

Install dependencies:

```
pacman --sync autoconf automake gcc git make python-pip
pip install --user poetry
```

Clone Core Lightning:

```
$ git clone https://github.com/ElementsProject/lightning.git
$ cd lightning
```

Build Core Lightning:

```
python -m poetry install
./configure
python -m poetry run make
```

Launch Core Lightning:

```
./lightningd/lightningd
```

To cross-compile for Android
--------------------

Make a standalone toolchain as per
https://developer.android.com/ndk/guides/standalone_toolchain.html.
For Core Lightning you must target an API level of 24 or higher.

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

    wget https://zlib.net/zlib-1.2.12.tar.gz
    tar xvf zlib-1.2.12.tar.gz
    cd zlib-1.2.12
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
    ./configure --disable-assembly --host=$target_host --prefix=$QEMU_LD_PREFIX
    make
    make install

Then, build Core Lightning with the following commands:

    ./configure
    make

To compile for Armbian
--------------------
For all the other Pi devices out there, consider using [Armbian](https://www.armbian.com).

You can compile in `customize-image.sh` using the instructions for Ubuntu.

A working example that compiles both bitcoind and Core Lightning for Armbian can
be found [here](https://github.com/Sjors/armbian-bitcoin-core).

To compile for Alpine
---------------------
Get dependencies:
```
apk update
apk add --virtual .build-deps ca-certificates alpine-sdk autoconf automake git libtool \
  gmp-dev sqlite-dev python3 py3-mako net-tools zlib-dev libsodium gettext
```
Clone lightning:
```
git clone https://github.com/ElementsProject/lightning.git
cd lightning
git submodule update --init --recursive
```
Build and install:
```
./configure
make
make install
```
Clean up:
```
cd .. && rm -rf lightning
apk del .build-deps
```
Install runtime dependencies:
```
apk add gmp libgcc libsodium sqlite-libs zlib
```

Additional steps
--------------------
Go to [README](https://github.com/ElementsProject/lightning/blob/master/README.md) for more information how to create an address, add funds, connect to a node, etc.
