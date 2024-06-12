---
title: "Docker Images"
slug: "docker-images"
hidden: false
createdAt: "2023-12-07T10:00:00.000Z"
updatedAt: "2023-12-07T10:00:00.000Z"
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
1. Ensure that your multiarch setup is working

2. Run script `tools/build-release.sh --push docker` to build `amd64`, `arm64v8`, `latest` and `multiarch` images and publish them on Dockerhub.

3. If you do not want to push the images directly on Dockerhub then run `tools/build-release.sh docker`. It will only create images locally but not push them to Dockerhub.


# Miscellaneous
## Testing Docker image

> 📘 QEMU Multiarch Setup
> 
> Before running a Docker image on a different platform than your local architecture, ensure that the `multiarch/qemu-user-static` setup is functioning correctly. Instructions for setting this up can be found [here](https://docs.corelightning.org/docs/docker-images#setting-up-multiarchqemu-user-static).


The Core Lightning (CLN) Docker image (platforms: `linux/amd64`, `linux/arm64`, `linux/arm/v7`) can be tested with a local Bitcoin regtest setup using the following command:

```shell
docker run -it --rm --platform=linux/amd64 --network=host -v '/root/.lightning:/root/.lightning' -v '/root/.bitcoin:/root/.bitcoin' elementsproject/lightningd:latest --network=regtest
```

## Test repro Dockerfiles and repro-build.sh:
1. Once the `cl-repro-<distro>` builder image is created, you can run it with:

```shell
docker run -it -v $(pwd):/repo cl-repro-noble /bin/bash
```

2. Get the Docker container ID of the above container using:

```shell
docker container ps
```

3. Start a shell in the container with:

```shell
docker exec -it <container-id-from-step2> bash
```

4. You can now run `. tools/repro-build.sh` with `--force-version` and `--force-mtime` arguments as needed.

## Execute other scripts for testing:

1. Create a directory named `lightning-poststart.d` in the `LIGHTNINGD_DATA` (`/root/.lightning`) directory.

2. Save executable scripts in this directory.

3. Run the container ensuring that:
   - The lightning data directory is mounted.
   - The lightning data directory path is defined with the environment variable `LIGHTNINGD_DATA`.

```shell
docker run -it --rm --platform=linux/amd64 --network=host -v '/root/.lightning:/root/.lightning' -v '/root/.bitcoin:/root/.bitcoin' -e LIGHTNINGD_DATA=/root/.lightning elementsproject/lightningd:latest --network=regtest

```

## Using CLI for CLN Node Running in the Docker Container

### From Host (Local CLI)

Use your local lightning-cli (if installed), ensuring that `lightning-dir` is configured with the local directory that is mounted to the container's `root/.lightning`.

```shell
sudo lightning-cli --regtest --lightning-dir=/root/.lightning getinfo
```

### Inside Docker Container
1. Get the container ID for the image `elementsproject/lightningd:latest`:

```shell
docker container ps
```

2. Run a new command in the running `lightningd` container:

```shell
docker exec -it <container-id-from-step1> bash
```

3. Use the container's `lightning-cli`:

```shell
lightning-cli --regtest getinfo
```
