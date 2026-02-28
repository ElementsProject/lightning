#!/bin/sh
# This script creates base images for focal, jammy, and noble. Then it builds the
# cl-repro-focal, cl-repro-jammy, and cl-repro-noble builder images. The base images are created using
# debootstrap, and the cl-repro images are created using the Dockerfiles in
# contrib/reprobuild. These builder images will finally be used to build the
# reproducible binaries.
# It automates the process described here:
# https://docs.corelightning.org/docs/repro#build-environment-setup
# https://docs.corelightning.org/docs/repro#builder-image-setup

# Assuming script will be used from the root of lightning directory
LIGHTNING_DIR=$PWD
# Remove '/contrib' from the end if it exists
LIGHTNING_DIR=$(echo "$LIGHTNING_DIR" | sed 's|/contrib$||')
echo "Lightning Directory: $LIGHTNING_DIR"

for v in focal jammy noble; do
  echo "Building base image for $v"
  sudo docker run -v "$LIGHTNING_DIR":/build ubuntu:$v \
	bash -c "apt-get update && apt-get install -y debootstrap && debootstrap $v /build/$v"
  sudo tar -C $v -c . | sudo docker import - $v
  echo "$v release:"
  sudo docker run ubuntu:$v cat /etc/lsb-release
  echo "Building CL repro $v:"
  # shellcheck disable=SC2024
  sudo docker build -t cl-repro-$v - < "$LIGHTNING_DIR"/contrib/reprobuild/Dockerfile.$v
done
