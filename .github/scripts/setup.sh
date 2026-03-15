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
     tshark \
     unzip \
     valgrind \
     wget \
     wireshark-common \
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

# Use the protoc compiler bundled with grpcio-tools so the compiler,
# gencode, and runtime versions are always in sync.
WRAPPER="$(cd "$(dirname "$0")" && pwd)/protoc-wrapper.sh"
export PROTOC="$WRAPPER"

# wireshark-common normally does this, but GH runners are special, so we
# do it explicitly
sudo groupadd -f wireshark
sudo chgrp wireshark /usr/bin/dumpcap
sudo chmod 750 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Add ourselves to the wireshark group (still need "sg wireshark..." for it to take effect)
sudo usermod -aG wireshark "$(id -nu)"

