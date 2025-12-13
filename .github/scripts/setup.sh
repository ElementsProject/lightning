#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
export RUST_VERSION=stable

sudo useradd -ms /bin/bash tester
sudo apt-get update -qq

# Add LLVM apt repository for consistent LLVM 18 installation across all steps
sudo apt-get install -qq --no-install-recommends -yy wget gnupg
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo apt-get update -qq

sudo apt-get -qq install --no-install-recommends --allow-unauthenticated -yy \
     autoconf \
     automake \
     binfmt-support \
     build-essential \
     clang-18 \
     libclang-rt-18-dev \
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
     llvm-18-tools \
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

# Add LLVM 18 tools to PATH (they're installed in /usr/lib/llvm-18/bin/)
export PATH="/usr/lib/llvm-18/bin:$PATH"
echo 'export PATH="/usr/lib/llvm-18/bin:$PATH"' | sudo tee /etc/profile.d/llvm-18-path.sh

# Create symlinks in /usr/bin for common LLVM tools so they're always accessible
echo "Creating symlinks for LLVM 18 tools in /usr/bin..."
sudo ln -sf /usr/lib/llvm-18/bin/llvm-profdata /usr/bin/llvm-profdata-18 || true
sudo ln -sf /usr/lib/llvm-18/bin/llvm-cov /usr/bin/llvm-cov-18 || true
sudo ln -sf /usr/bin/llvm-profdata-18 /usr/bin/llvm-profdata || true
sudo ln -sf /usr/bin/llvm-cov-18 /usr/bin/llvm-cov || true

echo "tester ALL=(root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/tester
sudo chmod 0440 /etc/sudoers.d/tester

"$(dirname "$0")"/install-bitcoind.sh

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
     -y --default-toolchain ${RUST_VERSION}

uv sync --all-extras --all-groups
# required for reckless till poetry to uv migration
uv tool install poetry

# We also need a relatively recent protobuf-compiler, at least 3.12.0,
# in order to support the experimental `optional` flag.

# BUT WAIT!  Gentoo wants this to match the version from the Python protobuf,
# which comes from the same tree.  Makes sense!

# And
#   grpcio-tools-1.69.0` requires `protobuf = ">=5.26.1,<6.0dev"`

# Now, protoc changed to date-based releases, BUT Python protobuf
# didn't, so Python protobuf 4.21.12 (in Ubuntu 23.04) corresponds to
# protoc 21.12 (which, FYI, is packaged in Ubuntu as version 3.21.12).

# In general protobuf version x.y.z corresponds to protoc version y.z

# Honorable mention go to Matt Whitlock for spelunking this horror with me!

PROTOC_VERSION=29.4
PB_REL="https://github.com/protocolbuffers/protobuf/releases"
curl -LO $PB_REL/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip
sudo unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local/
sudo chmod a+x /usr/local/bin/protoc
export PROTOC=/usr/local/bin/protoc
export PATH=$PATH:/usr/local/bin
env
ls -lha /usr/local/bin
