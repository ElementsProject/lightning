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

```
export DOCKER_CLI_EXPERIMENTAL=enabled
```

After adding it, source your shell profile file or restart your shell to apply the changes.

2. Create a new builder instance  
   By default, Docker uses the "legacy" builder. You need to create a new builder instance that uses BuildKit. To create a new builder instance, use the following command:

```
docker buildx create --use
```

The --use flag sets the newly created builder as the current one.

# Setting up multiarch/qemu-user-static

1. Check Buildx is working  
   Use the `docker buildx inspect --bootstrap` command to verify that Buildx is working correctly. The `--bootstrap` option ensures the builder instance is running before inspecting it. The output should look something like this:

```
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

```
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

4. Confirm QEMU is working

Again run `docker buildx inspect --bootstrap` command to verify that `linux/arm64` is in the list of platforms.

```
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
