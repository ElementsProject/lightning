#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
export BITCOIN_VERSION=0.20.1
export ELEMENTS_VERSION=0.18.1.8
export RUST_VERSION=nightly

sudo useradd -ms /bin/bash tester
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
     libgmp-dev \
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
     xsltproc \
     zlib1g-dev

echo "tester ALL=(root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/tester
sudo chmod 0440 /etc/sudoers.d/tester

(
    cd /tmp/ || exit 1
    wget https://storage.googleapis.com/c-lightning-tests/bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.bz2
    wget -q https://storage.googleapis.com/c-lightning-tests/elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.bz2
    tar -xjf bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.bz2
    tar -xjf elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.bz2
    sudo mv bitcoin-$BITCOIN_VERSION/bin/* /usr/local/bin
    sudo mv elements-$ELEMENTS_VERSION/bin/* /usr/local/bin
    rm -rf \
       bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz \
       bitcoin-$BITCOIN_VERSION \
       elements-$ELEMENTS_VERSION-x86_64-linux-gnu.tar.bz2 \
       elements-$ELEMENTS_VERSION
)

if [ "$RUST" == "1" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
      -y --default-toolchain ${RUST_VERSION}
fi
