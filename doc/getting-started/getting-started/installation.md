---
title: "Installation"
slug: "installation"
excerpt: "Core lightning is available on many platforms and environments. Learn how to install on your preferred platform."
hidden: false
createdAt: "2022-11-18T14:32:02.251Z"
updatedAt: "2023-07-13T05:08:44.966Z"
---
# Binaries

If you're on Ubuntu, you need to install bitcoind:


```shell
sudo apt-get install -y software-properties-common
sudo snap install bitcoin-core
sudo snap refresh --hold bitcoin-core	# To prevent automated update of bitcoin-core
sudo ln -s /snap/bitcoin-core/current/bin/bitcoin{d,-cli} /usr/local/bin/
```

Then you can fetch a pre-compiled binary from the [releases](https://github.com/ElementsProject/lightning/releases) page on GitHub. Core Lightning provides binaries for both Ubuntu and Fedora distributions. Normally these binaries are extracted into /usr/local:

```shell
sudo tar -xvf <release>.tar.xz -C /usr/local --strip-components=2
```

If you're on a different distribution or OS, you can compile the source by following the instructions from [Installing from Source](<>).

# Docker

To install the Docker image for the latest stable release: 

```shell
docker pull elementsproject/lightningd:latest
```

To install for a specific version, for example, 24.05:

```shell
docker pull elementsproject/lightningd:v24.05
```

See all of the docker images for Core Lightning on [Docker Hub](https://hub.docker.com/r/elementsproject/lightningd/tags).

# Third-party apps

For a GUI experience, you can install and use Core Lightning via a variety of third-party applications such as [Ride the Lightning](https://www.ridethelightning.info/), [Umbrel](https://getumbrel.com/), [BTCPayServer](https://btcpayserver.org/), [Raspiblitz](https://raspiblitz.org/), [Embassy](https://start9.com/). 

Core Lightning is also available on nixOS via the [nix-bitcoin](https://github.com/fort-nix/nix-bitcoin/) project.

# Installing from source

To build Core Lightning in a reproducible way, follow the steps at [Reproducible builds for Core Lightning](doc:repro).

## Library Requirements

You will need several development libraries:

- libsqlite3: for database support.
- zlib: for compression routines.

For actually doing development and running the tests, you will also need:

- pip3: to install python-bitcoinlib
- valgrind: for extra debugging checks

You will also need a version of bitcoind with segregated witness and `estimatesmartfee` with `ECONOMICAL` mode support, such as the 0.16 or above.

## To Build on Ubuntu

OS version: Ubuntu 15.10 or above

Get dependencies:

```shell
sudo apt-get update
sudo apt-get install -y \
  jq autoconf automake build-essential git libtool libsqlite3-dev libffi-dev \
  python3 python3-pip net-tools zlib1g-dev libsodium-dev gettext
pip3 install --upgrade pip
pip3 install --user poetry
```

If you don't have Bitcoin installed locally you'll need to install that as well. It's now available via [snapd](https://snapcraft.io/bitcoin-core).

```shell
sudo apt-get install snapd
sudo snap install bitcoin-core
# Snap does some weird things with binary names; you'll
# want to add a link to them so everything works as expected
sudo ln -s /snap/bitcoin-core/current/bin/bitcoin{d,-cli} /usr/local/bin/
```

Clone lightning:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning
```

Checkout a release tag:

```shell
git checkout v24.05
```

For development or running tests, get additional dependencies:

```shell
sudo apt-get install -y valgrind libpq-dev shellcheck cppcheck \
  libsecp256k1-dev lowdown
pip3 install pytest
```

If you can't install `lowdown`, a version will be built in-tree.

If you want to build the Rust plugins (currently, cln-grpc):

```shell
sudo apt-get install -y cargo rustfmt protobuf-compiler
```

There are two ways to build core lightning, and this depends on how you want use it.

To build cln to just install a tagged or master version you can use the following commands:

```shell
pip3 install --upgrade pip
pip3 install mako
pip3 install grpcio-tools
./configure
make
sudo make install
```

> 📘 
> 
> If you want disable Rust because you do not want use it or simple you do not want the grpc-plugin, you can use `./configure --disable-rust`.

To build core lightning for development purpose you can use the following commands:

```shell
pip3 install poetry
poetry shell
```

This will put you in a new shell to enter the following commands:

```shell
poetry install
./configure
make
make check VALGRIND=0
```

Optionally, add `-j$(nproc)` after `make` to speed up compilation. (e.g. `make -j$(nproc)`)

Running lightning:

```shell
bitcoind &
./lightningd/lightningd &
./cli/lightning-cli help
```

## To Build on Fedora

OS version: Fedora 27 or above

Get dependencies:

```shell
sudo dnf update -y && \
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
                jq \
                zlib-devel \
				libsodium-devel && \
        sudo dnf clean all
```

Make sure you have [bitcoind](https://github.com/bitcoin/bitcoin) available to run.

Clone lightning:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning
```

Checkout a release tag:

```shell
git checkout v24.05
```

Build and install lightning:

```shell
./configure
make
sudo make install
```

Running lightning (mainnet):

```shell
bitcoind &
lightningd --network=bitcoin
```

Running lightning on testnet:

```shell
bitcoind -testnet &
lightningd --network=testnet
```

## To Build on FreeBSD

OS version: FreeBSD 11.1-RELEASE or above

```shell
pkg install git python py39-pip gmake libtool gmp sqlite3 postgresql13-client gettext autotools
https://github.com/ElementsProject/lightning.git
pip install --upgrade pip
pip3 install mako
./configure
gmake -j$(nproc)
gmake install
```

Alternatively, Core Lightning is in the FreeBSD ports, so install it as any other port (dependencies are handled automatically):

```shell
# pkg install c-lightning
```

If you want to compile locally and fiddle with compile time options:

```shell
# cd /usr/ports/net-p2p/c-lightning && make install
```

See `/usr/ports/net-p2p/c-lightning/Makefile` for instructions on how to build from an arbitrary git commit, instead of the latest release tag.

> 📘 
> 
> Make sure you've set an utf-8 locale, e.g. `export LC_CTYPE=en_US.UTF-8`, otherwise manpage installation may fail.

Running lightning:

Configure bitcoind, if not already: add `rpcuser=<foo>` and `rpcpassword=<bar>` to `/usr/local/etc/bitcoin.conf`, maybe also `testnet=1`.

Configure lightningd: copy `/usr/local/etc/lightningd-bitcoin.conf.sample` to  
`/usr/local/etc/lightningd-bitcoin.conf` and edit according to your needs.

```shell
# service bitcoind start
# service lightningd start
# lightning-cli --rpc-file /var/db/c-lightning/bitcoin/lightning-rpc --lightning-dir=/var/db/c-lightning help
```

## To Build on OpenBSD

OS version: OpenBSD 7.3

Install dependencies:

```shell
pkg_add git python gmake py3-pip libtool gettext-tools
pkg_add automake # (select highest version, automake1.16.2 at time of writing)
pkg_add autoconf # (select highest version, autoconf-2.69p2 at time of writing)
```

Install `mako` otherwise we run into build errors:

```shell
pip3.8 install --user poetry
poetry install
```

Add `/home/<username>/.local/bin` to your path:

`export PATH=$PATH:/home/<username>/.local/bin`

Needed for `configure`:

```shell
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.16
./configure
```

Finally, build `c-lightning`:

`gmake`

## To Build on NixOS

Use nix-shell launch a shell with a full Core Lightning dev environment:

```shell
nix-shell -Q -p gdb sqlite autoconf git clang libtool sqlite autoconf \
autogen automake gmp zlib gettext libsodium poetry 'python3.withPackages (p: [p.bitcoinlib])' \
valgrind --run "./configure && poetry shell"
poetry install
make
```

## To Build on macOS

Assuming you have Xcode and Homebrew installed. Install dependencies:

```shell
brew install autoconf automake libtool python3 gnu-sed gettext libsodium protobuf
export PATH="/usr/local/opt:$PATH"
```

If you need SQLite (or get a SQLite mismatch build error):

```shell
brew install sqlite
export LDFLAGS="-L/usr/local/opt/sqlite/lib"
export CPPFLAGS="-I/usr/local/opt/sqlite/include"
```

Some library paths are different when using `homebrew` on Macs with Apple silicon, therefore the following two variables need to be set for Macs with Apple silicon:

```shell
export CPATH=/opt/homebrew/include
export LIBRARY_PATH=/opt/homebrew/lib
```

If you need Python 3.x for mako (or get a mako build error):

```shell
brew install pyenv
echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.bash_profile
source ~/.bash_profile
pyenv install 3.8.10
pip install --upgrade pip
pip install poetry
```

If you don't have bitcoind installed locally you'll need to install that as well:

```shell
brew install berkeley-db4 boost miniupnpc pkg-config libevent
git clone https://github.com/bitcoin/bitcoin
cd bitcoin
./autogen.sh
./configure
make src/bitcoind src/bitcoin-cli && make install
```

Clone lightning:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning
```

Checkout a release tag:

```shell
git checkout v24.05
```

Build lightning:

```shell
poetry install
./configure
poetry run make
```

Running lightning:

> 📘 
> 
> Edit your `~/Library/Application\ Support/Bitcoin/bitcoin.conf`to include `rpcuser=<foo>` and `rpcpassword=<bar>` first, you may also need to include `testnet=1`.

```shell
bitcoind &
./lightningd/lightningd &
./cli/lightning-cli help
```

To install the built binaries into your system, you'll need to run `make install`:

```shell
make install
```

On a Mac with Apple silicon, you may need to use this command instead:

```shell
sudo PATH="/usr/local/opt:$PATH"  LIBRARY_PATH=/opt/homebrew/lib CPATH=/opt/homebrew/include make install
```

## To Build on Arch Linux

Install dependencies:

```shell
pacman --sync autoconf automake gcc git make python-pip
pip install --user poetry
```

Clone Core Lightning:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning
```

Build Core Lightning:

```shell
python -m poetry install
./configure
python -m poetry run make
```

Launch Core Lightning:

```
./lightningd/lightningd
```

## To cross-compile for Android

Make a standalone toolchain as per <https://developer.android.com/ndk/guides/standalone_toolchain.html>.  
For Core Lightning you must target an API level of 24 or higher.

Depending on your toolchain location and target arch, source env variables such as:

```shell
export PATH=$PATH:/path/to/android/toolchain/bin
# Change next line depending on target device arch
target_host=arm-linux-androideabi
export AR=$target_host-ar
export AS=$target_host-clang
export CC=$target_host-clang
export CXX=$target_host-clang++
export LD=$target_host-ld
export STRIP=$target_host-strip
```

Two makefile targets should not be cross-compiled so we specify a native CC:

```shell
make CC=clang clean ccan/tools/configurator/configurator
make clean -C ccan/ccan/cdump/tools \
  && make CC=clang -C ccan/ccan/cdump/tools
```

Install the `qemu-user` package.  
This will allow you to properly configure the build for the target device environment.  
Build with:

```shell
BUILD=x86_64 MAKE_HOST=arm-linux-androideabi \
  make PIE=1 \
  CONFIGURATOR_CC="arm-linux-androideabi-clang -static"
```

## To cross-compile for Raspberry Pi

Obtain the [official Raspberry Pi toolchains](https://github.com/raspberrypi/tools). This document assumes compilation will occur towards the Raspberry Pi 3 (arm-linux-gnueabihf as of Mar. 2018).

Depending on your toolchain location and target arch, source env variables will need to be set. They can be set from the command line as such:

```shell
export PATH=$PATH:/path/to/arm-linux-gnueabihf/bin
# Change next line depending on specific Raspberry Pi device
target_host=arm-linux-gnueabihf
export AR=$target_host-ar
export AS=$target_host-as
export CC=$target_host-gcc
export CXX=$target_host-g++
export LD=$target_host-ld
export STRIP=$target_host-strip
```

Install the `qemu-user` package. This will allow you to properly configure the  
build for the target device environment.  
Config the arm elf interpreter prefix:

```shell
export QEMU_LD_PREFIX=/path/to/raspberry/arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf/arm-linux-gnueabihf/sysroot/
```

Obtain and install cross-compiled versions of sqlite3 and zlib:

Download and build zlib:

```shell
wget https://zlib.net/fossils/zlib-1.2.13.tar.gz
tar xvf zlib-1.2.13.tar.gz
cd zlib-1.2.13
./configure --prefix=$QEMU_LD_PREFIX
make
make install
```

Download and build sqlite3:

```shell
wget https://www.sqlite.org/2018/sqlite-src-3260000.zip
unzip sqlite-src-3260000.zip
cd sqlite-src-3260000
./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host=$target_host --prefix=$QEMU_LD_PREFIX
make
make install
```

Then, build Core Lightning with the following commands:

```
./configure
make
```

## To compile for Armbian

For all the other Pi devices out there, consider using [Armbian](https://www.armbian.com).

You can compile in `customize-image.sh` using the instructions for Ubuntu.

A working example that compiles both bitcoind and Core Lightning for Armbian can  
be found [here](https://github.com/Sjors/armbian-bitcoin-core).

## To compile for Alpine

Get dependencies:

```shell
apk update
apk add --virtual .build-deps ca-certificates alpine-sdk autoconf automake git libtool \
sqlite-dev python3 py3-mako net-tools zlib-dev libsodium gettext
```

Clone lightning:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning
git submodule update --init --recursive
```

Build and install:

```shell
./configure
make
make install
```

Clean up:

```shell
cd .. && rm -rf lightning
apk del .build-deps
```

Install runtime dependencies:

```shell
apk add libgcc libsodium sqlite-libs zlib
```

## Python plugins

Python plugins will be installed with the `poetry install` step mentioned above fron development setup. 

Other users will need some Python packages if python plugins are used. Unfortunately there are some Python packages which are not packaged in Ubuntu, and so force installation will be needed (Flag `--user` is recommended which will install them in user's own .local directory, so at least the risk of breaking Python globally can be avoided!).

### clnrest

Installation steps for clnrest are:

```
sudo apt-get install python3-json5 python3-flask python3-gunicorn
pip3 install --user flask-cors flask-restx pyln-client flask-socketio gevent gevent-websocket
```

### wss-proxy

Below libraries are required for wss-proxy:

```
pip3 install --user pyln-client websockets
```
