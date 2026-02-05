#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
export RUST_VERSION=stable

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
     gnupg \
     jq \
     libc6-dev-arm64-cross \
     libc6-dev-armhf-cross \
     libev-dev \
     libevent-dev \
     libffi-dev \
     libicu-dev \
     libpq-dev \
     libprotobuf-c-dev \
     libsodium-dev \
     libsqlite3-dev \
     libssl-dev \
     pkg-config \
     libtool \
     libxml2-utils \
     locales \
     lowdown \
     net-tools \
     postgresql \
     python3 \
     python3-dev \
     python3-pip \
     python3-setuptools \
     qemu-system \
     qemu-system-arm \
     qemu-user-static \
     shellcheck \
     software-properties-common \
     sudo \
     tcl \
     tclsh \
     unzip \
     valgrind \
     wget \
     xsltproc \
     systemtap-sdt-dev \
     zlib1g-dev

echo "tester ALL=(root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/tester
sudo chmod 0440 /etc/sudoers.d/tester

"$(dirname "$0")"/install-bitcoind.sh

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
     -y --default-toolchain ${RUST_VERSION}

uv sync --all-extras --all-groups
# required for reckless till poetry to uv migration
uv tool install poetry

# Install protoc wrapper that uses grpcio-tools bundled compiler.
# This ensures the protoc version matches the protobuf Python package,
# avoiding version mismatches between generated code and runtime.
sudo install -m 755 contrib/protoc /usr/local/bin/protoc
