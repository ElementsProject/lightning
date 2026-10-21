---
title: Docker Images
slug: docker-images
privacy:
  view: public
---
# Setting up Docker's Buildx

Docker Buildx is an extension of Docker's build command, that provides a more efficient way to create images. It is part of Docker 19.03 and can also be manually installed as a CLI plugin for older versions.

1. Enable Docker CLI experimental features  
   Docker CLI experimental features are required to use Buildx. Enable them by setting the DOCKER_CLI_EXPERIMENTAL environment variable to enabled.  
   You can do this by adding the following line to your shell profile file (.bashrc, .zshrc, etc.):

```shell
export DOCKER_CLI_EXPERIMENTAL=enabled
```

After adding it, source your shell profile file or restart your shell to apply the changes.

2. Create a new builder instance  
   By default, Docker uses the "legacy" builder. You need to create a new builder instance that uses BuildKit. To create a new builder instance, use the following command:

```shell
docker buildx create --use
```

The --use flag sets the newly created builder as the current one.

# Setting up multiarch/qemu-user-static

1. Check Buildx is working  
   Use the `docker buildx inspect --bootstrap` command to verify that Buildx is working correctly. The `--bootstrap` option ensures the builder instance is running before inspecting it. The output should look something like this:

```shell
Name:          my_builder
Driver:        docker-container
Last Activity: 2023-06-13 04:37:30 +0000 UTC
Nodes:
Name:      my_builder0
Endpoint:  unix:///var/run/docker.sock
Status:    running
Buildkit:  v0.11.6
Platforms: linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/amd64/v4, linux/386
```

2. Install `binfmt-support` and `qemu-user-static` if not installed already.

```shell
sudo apt-get update
sudo apt-get install docker.io binfmt-support qemu-user-static
sudo systemctl restart docker
```

3. Setup QEMU to run binaries from multiple architectures

```shell
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

4. Confirm QEMU is working

Again run `docker buildx inspect --bootstrap` command to verify that `linux/arm64` is in the list of platforms.

```shell
Name:          my_builder
Driver:        docker-container
Last Activity: 2023-06-13 04:37:30 +0000 UTC
Nodes:
Name:      my_builder0
Endpoint:  unix:///var/run/docker.sock
Status:    running
Buildkit:  v0.11.6
Platforms: linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/amd64/v4, linux/386, linux/arm64, linux/riscv64, linux/ppc64, linux/ppc64le, linux/s390x, linux/mips64le, linux/mips64
```

# Building/publishing images on Dockerhub

Release images are built and published by the release driver, from the same
static tarballs the release signs — the image compiles nothing:

1. Ensure that your multiarch setup is working (the driver smoke-tests every
   platform of the image under `binfmt` before it is published).

2. `tools/reprobuild docker` builds one multi-arch image into a local OCI layout
   under `release/docker/` and records its per-architecture digests in
   `DIGESTS-<version>` and `DIGESTS-<version>-armhf`, which the release
   manifests sign. Nothing is pushed.

3. `tools/reprobuild publish` pushes it, with `skopeo copy --all
   --preserve-digests`, so the digests users pull are the digests that were
   signed. Add `--latest` to also move the `latest` tag; it is never implied and
   never applied to an rc.

See the [release checklist](https://docs.corelightning.org/docs/release-checklist)
for where those steps sit in a release.


# Miscellaneous
## Testing Docker image

> 📘 QEMU Multiarch Setup
> 
> Before running a Docker image on a different platform than your local architecture, ensure that the `multiarch/qemu-user-static` setup is functioning correctly. Instructions for setting this up can be found [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).


The Core Lightning (CLN) Docker image (platforms: `linux/amd64`, `linux/arm64`, `linux/arm/v7`) can be tested with a local Bitcoin regtest setup using the following command:

```shell
docker run -it --rm --platform=linux/amd64 --network=host -v '/root/.lightning:/root/.lightning' -v '/root/.bitcoin:/root/.bitcoin' elementsproject/lightningd:latest --network=regtest
```

## Testing the reproducible build

There are no `cl-repro-<distro>` builder images any more: the release is built
by a Nix derivation inside a digest-pinned `nixos/nix` container, and
`tools/reprobuild` is the only entry point. To poke at the build environment:

```shell
tools/reprobuild build amd64            # one row
tools/reprobuild build amd64 --rebuild  # and have Nix prove it reproduces
```

`--host-nix` uses your own Nix instead of the container, which is faster if you
have one. See the [reproducible builds
page](https://docs.corelightning.org/docs/repro) for the full flow.

## Execute other scripts for testing:

1. Create a directory named `lightning-poststart.d` in the `LIGHTNINGD_DATA` (`/root/.lightning`) directory.

2. Save executable scripts in this directory.

3. Run the container ensuring that:
   - The lightning data directory is mounted.
   - The lightning data directory path is defined with the environment variable `LIGHTNINGD_DATA`.

```shell
docker run -it --rm --platform=linux/amd64 --network=host -v '/root/.lightning:/root/.lightning' -v '/root/.bitcoin:/root/.bitcoin' -e LIGHTNINGD_DATA=/root/.lightning elementsproject/lightningd:latest --network=regtest

```

## Replace the `hsmd` subdaemon with VLS `remote_hsmd_socket`:

1. This setup assumes that both `bitcoind` and `vlsd` will be running on your host system.

2. Start your `bitcoind` node on the local machine.

3. Start `vlsd` locally with your preferred configuration. For example:

```shell
export LIGHTNING_VLS_DIR=/root/.lightning
export GREENLIGHT_VERSION="v25.12"
export VLS_CLN_VERSION="v25.12"
export VLS_NETWORK="regtest"
export BITCOIND_RPC_URL="http://user:password@127.0.0.1:18443"
export RUST_LOG=info
export RUST_BACKTRACE=1

/home/validating-lightning-signer/target/release/vlsd \
  --datadir "$LIGHTNING_VLS_DIR"/.lightning-signer \
  --network regtest \
  --connect http://127.0.0.1:7701 \
  --rpc-server-address 127.0.0.1 \
  --rpc-server-port 8000 \
  --rpc-user vlsuser \
  --rpc-pass vlspassword \
  --log-level info
```

4. Finally, run the Core Lightning node:

> 🚧 The `-vls` image flavour is not published at the moment
>
> Core Lightning offers channel splicing by default and refuses to start with a
> signer that cannot sign splice transactions, which no released VLS does yet.
> The `-vls` image and the released `remote_hsmd_socket` binaries are therefore
> suspended — 4.1 below describes how they work and will work again, but for now
> use 4.2 with a signer you built yourself.

4.1 Either by utilizing our docker image flavor `elementsproject/lightningd:v25.12-vls` which comes with pre-built `remote_hsmd_socket` binaries. The image sets `VLS_ENABLED`, `VLS_CLN_VERSION` and the network for you; you still have to pass `BITCOIND_RPC_URL`, because the signer validates against the chain itself and its bitcoind need not be the node's.

```shell
docker run -it --rm -d \
  --platform=linux/amd64 \
  --network=host \
  -v '/root/.lightning:/root/.lightning' \
  -v '/root/.bitcoin:/root/.bitcoin' \
  -e GREENLIGHT_VERSION="v25.12" \
  -e VLS_CLN_VERSION="v25.12" \
  -e VLS_NETWORK="regtest" \
  -e BITCOIND_RPC_URL="http://user:password@127.0.0.1:18443" \
  -e LIGHTNINGD_NETWORK=regtest \
  elementsproject/lightningd:v25.12-vls \
  --bitcoin-rpcconnect=0.0.0.0 \
  --bitcoin-rpcuser=user \
  --bitcoin-rpcpassword=password \
  --network=regtest \
  --database-upgrade=true \
  --bitcoin-datadir=/root/.bitcoin \
  --log-level=debug \
  --announce-addr=127.0.0.1:19750 \
  --bind-addr=localhost:8989 \
  --bind-addr=ws:127.0.0.1:5020 \
  --bind-addr=0.0.0.0:19750 \
  --bitcoin-rpcport=18443 \
  --clnrest-port=3020 \
  --grpc-port=9740 \
  --subdaemon=hsmd:/var/lib/vls/bin/remote_hsmd_socket
```

4.2 Or, by replacing subdaemon `hsmd` with your mounted `remote_hsmd_socket`:

```shell
docker run -it --rm -d \
  --platform=linux/amd64 \
  --network=host \
  -v '/root/.lightning:/root/.lightning' \
  -v '/root/.bitcoin:/root/.bitcoin' \
  -v '/root/vls/target/release/remote_hsmd_socket:/var/lib/vls/bin/remote_hsmd_socket'
  -e GREENLIGHT_VERSION="v25.12" \
  -e VLS_CLN_VERSION="v25.12" \
  -e VLS_NETWORK="regtest" \
  -e BITCOIND_RPC_URL="http://user:password@127.0.0.1:18443" \
  -e LIGHTNINGD_NETWORK=regtest \
  elementsproject/lightningd:v25.12 \
  --bitcoin-rpcconnect=0.0.0.0 \
  --bitcoin-rpcuser=user \
  --bitcoin-rpcpassword=password \
  --network=regtest \
  --database-upgrade=true \
  --bitcoin-datadir=/root/.bitcoin \
  --log-level=debug \
  --announce-addr=127.0.0.1:19750 \
  --bind-addr=localhost:8989 \
  --bind-addr=ws:127.0.0.1:5020 \
  --bind-addr=0.0.0.0:19750 \
  --bitcoin-rpcport=18443 \
  --clnrest-port=3020 \
  --grpc-port=9740 \
  --subdaemon=hsmd:/var/lib/vls/bin/remote_hsmd_socket
```
