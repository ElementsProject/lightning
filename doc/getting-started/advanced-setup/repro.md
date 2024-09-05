---
title: "Reproducible builds"
slug: "repro"
hidden: false
createdAt: "2023-01-25T10:37:03.476Z"
updatedAt: "2023-07-12T13:26:52.005Z"
---
Reproducible builds close the final gap in the lifecycle of open-source projects by allowing maintainers to verify and certify that a given binary was indeed produced by compiling an unmodified version of the publicly available source. In particular the maintainer certifies that the binary corresponds a) to the exact version of the and b) that no malicious changes have been applied before or after the compilation.

Core Lightning has provided a manifest of the binaries included in a release, along with signatures from the maintainers since version 0.6.2.

The steps involved in creating reproducible builds are:

- Creation of a known environment in which to build the source code
- Removal of variance during the compilation (randomness, timestamps, etc)
- Packaging of binaries
- Creation of a manifest (`SHA256SUMS` file containing the crytographic hashes of the binaries and packages)
- Signing of the manifest by maintainers and volunteers that have reproduced the files in the manifest starting from the source.

The bulk of these operations is handled by the [`repro-build.sh`](https://github.com/ElementsProject/lightning/blob/master/tools/repro-build.sh) script, but some manual operations are required to setup the build environment. Since a binary is built against platorm specific libraries we also need to replicate the steps once for each OS distribution and architecture, so the majority of this guide will describe how to set up those starting from a minimal trusted base. This minimal trusted base in most cases is the official installation medium from the OS provider.

Note: Since your signature certifies the integrity of the resulting binaries, please familiarize youself with both the [`repro-build.sh`](https://github.com/ElementsProject/lightning/blob/master/tools/repro-build.sh) script, as well as with the setup instructions for the build environments before signing anything.

# Build Environment Setup

The build environments are a set of docker images that are created directly from the installation mediums and repositories from the OS provider. The following sections describe how to create those images. Don't worry, you only have to create each image once and can then reuse the images for future builds.

## Base image creation

Depending on the distribution that we want to build for the instructions to create a base image can vary. In the following sections we discuss the specific instructions for each distribution, whereas the instructions are identical again once we have the base image.

### Debian / Ubuntu and derivative OSs

For operating systems derived from Debian we can use the `debootstrap` tool to build a minimal OS image, that can then be transformed into a docker image. The packages for the minimal OS image are directly downloaded from the installation repositories operated by the OS provider.

We cannot really use the `debian` and `ubuntu` images from the docker hub, mainly because it'd be yet another trusted third party, but it is also complicated by the fact that the images have some of the packages updated. The latter means that if we disable the `updates` and `security` repositories for `apt` we find ourselves in a situation where we can't install any additional packages (wrongly updated packages depending on the versions not available in  
the non-updated repos).

The following table lists the codenames of distributions that we currently support:

- Ubuntu 20.04:
  - Distribution Version: 20.04
  - Codename: focal
- Ubuntu 22.04:
  - Distribution Version: 22.04
  - Codename: jammy
- Ubuntu 24.04:
  - Distribution Version: 24.04
  - Codename: noble

Depending on your host OS release you might not have `debootstrap` manifests for versions newer than your host OS. Due to this we run the `debootstrap` commands in a container of the latest version itself:

```shell
for v in focal jammy noble; do
  echo "Building base image for $v"
  sudo docker run --rm -v $(pwd):/build ubuntu:$v \
	bash -c "apt-get update && apt-get install -y debootstrap && debootstrap $v /build/$v"
  sudo tar -C $v -c . | sudo docker import - $v
done
```

Verify that the image corresponds to our expectation and is runnable:

```shell
sudo docker run ubuntu:noble cat /etc/lsb-release
```

Which should result in the following output for `noble`:

```shell
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=24.04
DISTRIB_CODENAME=noble
DISTRIB_DESCRIPTION="Ubuntu 24.04 LTS"
```

## Builder image setup

Once we have the clean base image we need to customize it to be able to build Core Lightning. This includes disabling the update repositories, downloading the build dependencies and specifying the steps required to perform the build.

For this purpose we have a number of Dockerfiles in the [`contrib/reprobuild`](https://github.com/ElementsProject/lightning/tree/master/contrib/reprobuild) directory that have the specific instructions for each base image.

We can then build the builder image by calling `docker build` and passing it the `Dockerfile`:

```shell
sudo docker build -t cl-repro-focal - < contrib/reprobuild/Dockerfile.focal
sudo docker build -t cl-repro-jammy - < contrib/reprobuild/Dockerfile.jammy
sudo docker build -t cl-repro-noble - < contrib/reprobuild/Dockerfile.noble
```

Since we pass the `Dockerfile` through `stdin` the build command will not create a context, i.e., the current directory is not passed to `docker` and it'll be independent of the currently checked out version. This also means that you will be able to reuse the docker image for future builds, and don't have to repeat this dance every time. Verifying the `Dockerfile` therefore is  
sufficient to ensure that the resulting `cl-repro-<codename>` image is reproducible.

The dockerfiles assume that the base image has the codename as its image name.

## Script cl-repro

The script `contrib/cl-repro.sh` covers above `Base image creation` and `Builder image setup` steps. You can skip these steps by simply running the `contrib/cl-repro.sh` script.

# Building using the builder image

Finally, after building enviornment setup we can perform the actual build.  At this point we have a container image that has been prepared to build reproducibly. As you can see from the `Dockerfile` above we assume the source git repository gets mounted as `/repo` in the docker container. The container will clone the repository to an internal path, in order to keep the repository clean, build the artifacts there, and then copy them back to `/repo/release`.  
We'll need the release directory available for this, so create it now if it doesn't exist:`mkdir release`, then we can simply execute the following command inside the git repository (remember to checkout the tag you are trying to build):

```bash
sudo docker run --rm -v $(pwd):/repo -ti cl-repro-focal
sudo docker run --rm -v $(pwd):/repo -ti cl-repro-jammy
sudo docker run --rm -v $(pwd):/repo -ti cl-repro-noble
```

The last few lines of output also contain the `sha256sum` hashes of all artifacts, so if you're just verifying the build those are the lines that are of interest to you:

```shell
ee83cf4948228ab1f644dbd9d28541fd8ef7c453a3fec90462b08371a8686df8  /repo/release/clightning-v0.9.0rc1-Ubuntu-18.04.tar.xz
94bd77f400c332ac7571532c9f85b141a266941057e8fe1bfa04f054918d8c33  /repo/release/clightning-v0.9.0rc1.zip
```

Repeat this step for each distribution and each architecture you wish to sign. Once all the binaries are in the `release/` subdirectory we can sign the hashes.

# Signing the release manifest

The release captain is in charge of creating the manifest, whereas contributors and interested bystanders may contribute their signatures to further increase trust in the binaries.

## Script build-release
1: Pull latest code from master

2: Run the `tools/build-release.sh bin-Fedora-28-amd64 bin-Ubuntu sign` script. This will create a release directory, build binaries for Fedora, and build binaries for Ubuntu (Focal, Jammy, and Noble). Finally, it will sign the ZIP, Fedora, and Ubuntu builds.

## Manual
The release captain creates the manifest as follows:

```shell
cd release/
sha256sum *v0.9.0* > SHA256SUMS
gpg -sb --armor SHA256SUMS
```

# Co-signing the release manifest

## Script build-release
1: Pull latest code from master.

2: Rename checksum files, shared by the release captain, to `SHA256SUMS-v($VERSION)` and `SHA256SUMS-v($VERSION).asc`.

2: Copy above files in the lightning directory.

3: Run `tools/build-release.sh --verify` script. It will build bineries for Ubuntu (Focal, Jammy & Noble), verify zip & ubuntu builds while copying Fedora checksums from the release captain's file.

4. Then send the resulting `release/SHA256SUMS.asc` file to the release captain so it can be merged with the other signatures into `SHASUMS.asc`.

## Manual
Co-maintainers and contributors wishing to add their own signature verify that the `SHA256SUMS` and `SHA256SUMS.asc` files created by the release captain matches their binaries before also signing the manifest:

```shell
cd release/
gpg --verify SHA256SUMS.asc
sha256sum -c SHA256SUMS
cat SHA256SUMS | gpg -sb --armor > SHA256SUMS.new
```

Then send the resulting `SHA256SUMS.new` file to the release captain so it can be merged with the other signatures into `SHASUMS.asc`.

# Verifying a reproducible build

You can verify the reproducible build in two ways:

- Repeating the entire reproducible build, making sure from scratch that the binaries match. Just follow the instructions above for this.
- Verifying that the downloaded binaries match the hashes in `SHA256SUMS` and that the signatures in `SHA256SUMS.asc` are valid.

Assuming you have downloaded the binaries, the manifest and the signatures into the same directory, you can verify the signatures with the following:

```shell
gpg --verify SHA256SUMS.asc
```

And you should see a list of messages like the following:

```shell
gpg: assuming signed data in 'SHA256SUMS'
gpg: Signature made Fr 08 Mai 2020 07:46:38 CEST
gpg:                using RSA key 15EE8D6CAB0E7F0CF999BFCBD9200E6CD1ADB8F1
gpg: Good signature from "Rusty Russell <rusty@rustcorp.com.au>" [full]
gpg: Signature made Fr 08 Mai 2020 12:30:10 CEST
gpg:                using RSA key B7C4BE81184FC203D52C35C51416D83DC4F0E86D
gpg: Good signature from "Christian Decker <decker.christian@gmail.com>" [ultimate]
gpg: Signature made Fr 08 Mai 2020 21:35:28 CEST
gpg:                using RSA key 30DE693AE0DE9E37B3E7EB6BBFF0F67810C1EED1
gpg: Good signature from "Lisa Neigut <niftynei@gmail.com>" [full]
```

If there are any issues `gpg` will print `Bad signature`, it might be because the signatures in `SHA256SUMS.asc` do not match the `SHA256SUMS` file, and could be the result of a filename change. Do not continue using the binaries, and contact the maintainers, if this is not the case, a failure here means that the verification failed.

Next we verify that the binaries match the ones in the manifest:

```shell
sha256sum -c SHA256SUMS
```

Producing output similar to the following:

```shell
sha256sum: clightning-v0.9.0-Fedora-28-amd64.tar.gz: No such file or directory
clightning-v0.9.0-Fedora-28-amd64.tar.gz: FAILED open or read
clightning-v0.9.0-Ubuntu-18.04.tar.xz: OK
clightning-v0.9.0.zip: OK
sha256sum: WARNING: 1 listed file could not be read
```

Notice that the two files we downloaded are marked as `OK`, but we're missing one file. If you didn't download that file this is to be expected, and is nothing to worry about. A failure to verify the hash would give a warning like the following:

```shell
sha256sum: WARNING: 1 computed checksum did NOT match
```

If both the signature verification and the manifest checksum verification succeeded, then you have just successfully verified a reproducible build and, assuming you trust the maintainers, are good to install and use the binaries. Congratulations! 🎉🥳