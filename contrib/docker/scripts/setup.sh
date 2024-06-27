#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
export BITCOIN_VERSION=27.1
export ELEMENTS_VERSION=23.2.1
export RUST_VERSION=nightly
export TZ="Europe/London"

sudo apt-get update -qq

sudo apt-get -qq install --no-install-recommends --allow-unauthenticated -yy \
     autoconf \
     automake \
     binfmt-support \
     build-essential \
     clang \
     cppcheck \
     docbook-xml \
     eatmydata \
     gcc-aarch64-linux-gnu \
     gcc-arm-linux-gnueabihf \
     gcc-arm-none-eabi \
     gettext \
     git \
     libc6-dev-arm64-cross \
     libc6-dev-armhf-cross \
     libpq-dev \
     libprotobuf-c-dev \
     libsqlite3-dev \
     libtool \
     libxml2-utils \
     locales \
     net-tools \
     postgresql \
     python-pkg-resources \
     python3 \
     python3-dev \
     python3-pip \
     python3-setuptools \
     qemu \
     qemu-system-arm \
     qemu-user-static \
     shellcheck \
     software-properties-common \
     sudo \
     tcl \
     unzip \
     valgrind \
     wget \
     jq \
     xsltproc \
     zlib1g-dev

(
    cd /tmp/ || exit 1
    wget https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz
    wget https://github.com/ElementsProject/elements/releases/download/elements-$ELEMENTS_VERSION/elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.gz
    tar -xzf bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz
    tar -xzf elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.gz
    sudo mv bitcoin-$BITCOIN_VERSION/bin/* /usr/local/bin
    sudo mv elements-$ELEMENTS_VERSION/bin/* /usr/local/bin
    rm -rf \
       bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz \
       bitcoin-$BITCOIN_VERSION \
       elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.gz \
       elements-$ELEMENTS_VERSION
)

if [ "$RUST" == "1" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
      -y --default-toolchain ${RUST_VERSION}
fi
