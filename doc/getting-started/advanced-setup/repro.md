---
title: Reproducible builds
slug: repro
privacy:
  view: public
---
[Reproducible builds](https://reproducible-builds.org/) close the final gap in the lifecycle of open-source projects by allowing anyone to verify that a given binary was produced by compiling publicly available source code.

Core Lightning has provided a manifest of the binaries included in a release, along with signatures from the maintainers, since version 0.6.2.

> 🚧 Status
>
> This page documents the Nix-based build introduced on the
> `prototype/nix-static` branch, driven by `tools/reprobuild`. All three
> architectures build, reproduce under `nix build --rebuild` and pass the
> release checks, and a co-signer's `verify` has reproduced every file in
> both manifests. What has not yet run against a real key is the signing
> itself.

The steps involved in creating reproducible builds are:

- Creation of a known environment in which to build the source code
- Removal of variance during the compilation (randomness, timestamps, etc)
- Packaging of binaries
- Creation of a manifest (`SHA256SUMS` file containing the cryptographic hashes of the binaries and packages)
- Signing of the manifest by maintainers and volunteers that have reproduced the files in the manifest starting from the source.

Note: Since your signature certifies the integrity of the resulting binaries, please familiarize yourself with the build setup before signing anything.

# The available binaries

Every release ships **one build per architecture**, not one per distribution. The binaries are statically linked against [musl libc](https://musl.libc.org/), so they carry no runtime dependency on the libc, OpenSSL, sqlite or libpq of the machine they run on, and the same tarball works on any Linux distribution for that architecture.

| Artifact | Architecture | Runs on | Notes |
|---|---|---|---|
| `clightning-<version>-static-amd64.tar.xz` | x86-64 | any Linux, x86-64 | baseline x86-64; uses hardware CRC32 where the CPU reports it |
| `clightning-<version>-static-arm64.tar.xz` | AArch64 (`arm64`) | any Linux, ARMv8-A and newer | Raspberry Pi 3, 4, 5, Zero 2 W; most ARM servers |
| `clightning-<version>-static-armhf.tar.xz` | 32-bit ARM (`armhf`) | any Linux, **ARMv7-A** hard-float and newer | Raspberry Pi 2 and newer. **Not** Pi 1 / Zero / Zero W, which are ARMv6. Signed in the separate `armhf` manifest — see the caveat under [Co-signing the release manifest](#co-signing-the-release-manifest) |
| `lightningd` Docker image | amd64, arm64, arm/v7 | Docker | built *from* the tarballs above, one multi-arch manifest. The `arm/v7` half inherits the `armhf` caveat below |
| `clightning-<version>.zip` | — | — | source archive |

What this means in practice:

- **There is no distribution dimension any more.** Earlier releases shipped
  `clightning-<version>-Ubuntu-22.04.tar.xz` and friends, one per distribution and
  version, because the binaries were dynamically linked against that distribution's
  libraries. Pick the tarball for your architecture instead.
- **32-bit ARM requires ARMv7-A with hardware floating point.** Raspberry Pi 1,
  Pi Zero and Pi Zero W are ARMv6 and are not supported; build from source there.
  On a Pi 3, 4 or 5 prefer the `arm64` tarball, even if you run a 32-bit userland —
  the hardware is ARMv8.
- **PostgreSQL and sqlite are both built in.** `--wallet=postgres://…` works out of
  the box; libpq is linked statically like everything else.
- **The binaries are stripped**, and each one keeps its GNU build-id so a crash
  report can still be resolved against the release. Debug symbols are not published.
- Every executable is a **static PIE** (`static-pie`), so ASLR still applies.
- **There is no Validating Lightning Signer binary and no `-vls` image in this
  release.** Core Lightning offers channel splicing by default and refuses to
  run with a signer that cannot sign splice transactions; no released VLS
  implements that yet, so the signer binary and the image built around it
  could only have been published unable to start. Both return, with the
  manifest lines that go with them, once upstream VLS signs splices. The build
  recipe stays in the tree (`tools/reprobuild vls`) for anyone who wants to
  build one anyway.

## Installing a tarball

The tarballs unpack over the filesystem root, with everything under `/usr`:

```shell
sudo tar -xvf clightning-<version>-static-<arch>.tar.xz -C /
```

Inspect one first with `tar -tvf` if you would rather see what it contains before
unpacking it over `/`, or unpack it somewhere harmless and copy what you need.

# Build environment setup

The build environment is a **pinned nixpkgs revision**, recorded in `flake.lock` in
the repository. There are no builder images to construct from installation media,
no package pin lists to refresh and no per-distribution setup: the compiler, every
library and every build tool are content-addressed store paths, fixed by that one
revision, and Nix builds them in a sandbox with no network access.

All you need is Nix with flakes enabled (`nix-command` and `flakes` in
`experimental-features`). The builds above are produced with Nix 2.31.3; if your
Nix cannot evaluate the flake, the driver can also run the whole build inside a
digest-pinned `nixos/nix` container instead of using your own Nix.

The release artifacts are built from **the same derivation as `packages.default`**,
evaluated as a static (and, for the arm rows, cross) variant — the flake's
`cln-release-static-amd64`, `cln-release-static-arm64` and
`cln-release-static-armhf` attributes, which are generated from the plain table
in `nix/release-rows`. The thing that gets tested hardest every release is
therefore the same thing Nix users install.

Two guards keep that sharing honest. `nix/release-rows` also records the nixpkgs
revision the release is *certified* against: if `flake.lock` moves, the release
attributes refuse to evaluate and `nix flake check` fails, in the commit that
moved it. And each row commits a short file under `nix/release-manifests/`
listing what that row is made of — its direct inputs with versions, the
toolchain versions, the build flags and the environment — so a change that
reaches the release shows up as a diff you can read without knowing Nix.

# Building

Check out the tag you are building and run the driver. It needs **docker,
coreutils and python3 (3.10 or newer)**, and nothing else: the driver is a
single standard-library script, and every Nix command runs inside a
digest-pinned `nixos/nix` container, with a store under
`~/.cache/cln-reprobuild`. If you have Nix yourself and want the faster loop,
add `--host-nix`.

```shell
tools/reprobuild build          # all three rows
tools/reprobuild build amd64    # or one
```

The driver refuses to build a release from a tree with uncommitted changes: Nix
caches the working tree it fetched, so the artifacts could otherwise be labelled
with a commit they were not built from.

The arm rows are cross-compiled from x86-64; no emulation is involved except for
the handful of build steps that run their own output, which use a QEMU taken from
the pinned closure rather than from the host's `binfmt` registration. That matters
for reproducibility: a build that relied on the host's `binfmt` would give a
different answer on a machine configured differently.

Each row prints the hash of the artifact it wrote, and then checks it — every
shipped executable must be stripped, position-independent, free of any embedded
library search path, and still carry its build-id:

```shell
reprobuild: wrote release/clightning-v25.12-static-amd64.tar.xz
57666565916779e12046cf8277e31554e1ce65ea08f3cd459694fb7101f85346  release/clightning-v25.12-static-amd64.tar.xz
check: OK (40 ELFs, all static-pie, stripped, with build-id)
```

The tarball is itself a Nix output, so `--rebuild` has Nix build it a second
time and compare against the store. That is a stronger statement than running
the driver twice, which is only a store hit, and it covers the exact bytes that
get signed rather than a `tar` run afterwards:

```shell
tools/reprobuild build amd64 --rebuild
```

The build takes 20–40 minutes per row on a modern 16-thread machine, and the first
run of a cross row also builds that architecture's toolchain, which can take
considerably longer.

The source archive is a Nix output too, built from the same tree rather than
assembled on your machine, so `tools/reprobuild zip` gives the same bytes
everywhere.

## ARM builds (arm64 and armv7)

Each ARM architecture has its own manifest and signatures: `SHA256SUMS-v<VERSION>-arm64` / `.asc` and `SHA256SUMS-v<VERSION>-armv7` / `.asc`. They are separate because they are reproduced differently (arm64 natively, armv7 cross-compiled), so you can verify and co-sign one without the other. Their output goes to `release-arm64/` and `release-armv7/`, not `release/`, so the manifests never mix.

- **arm64** builds natively, on an arm64 machine. Running `contrib/cl-repro.sh` there creates the builder images as `cl-repro-<codename>-arm64`, and `tools/build-release.sh bin-Ubuntu-<codename>-arm64` (or `docker run --rm -v $(pwd):/repo -ti cl-repro-<codename>-arm64`) builds the tarball using the pinned packages in `tools/repro-build.arm64.sh`.
- **armv7** is cross-compiled on an amd64 machine, in the same `cl-repro-<codename>` image as the amd64 build, using the pinned toolchain and armhf libraries in `tools/repro-build.armv7.sh`. The build runs a few armv7 programs, so register qemu with the kernel first (once per boot):

  ```shell
  docker run --privileged --rm tonistiigi/binfmt --install arm
  tools/build-release.sh bin-Ubuntu-noble-armv7
  # or directly:
  docker run --rm -v $(pwd):/repo -e REPRO_ARCH=armv7 -ti cl-repro-noble
  ```

Once the tarballs are built, `tools/sign-release-arm.sh v<VERSION> arm64` (or `armv7`) creates and signs `SHA256SUMS-v<VERSION>-arm64` (or `-armv7`).

# Signing the release manifest

The release captain is in charge of creating the manifest, whereas contributors and
interested bystanders may contribute their signatures to further increase trust in
the binaries.

There are **two** manifests, because one architecture cannot currently be
confirmed by anyone but the captain (see the caveat below):

- `SHA256SUMS-<version>` — every release file except the 32-bit ARM ones. Every
  co-signer is expected to reproduce and sign this.
- `SHA256SUMS-<version>-armhf` — the `armhf` tarball and the `armhf` image
  digests. Co-signers sign this **only if** they actually reproduced it, and
  simply omit their signature otherwise.

The release captain writes and signs both with one command:

```shell
tools/reprobuild sign
```

Each manifest begins with a comment block recording what the build consumed —
the commit, the flake's `narHash`, whether submodules were included, the
timestamp baked into the artifacts, and the certified nixpkgs revision.
`sha256sum` ignores those lines; they are there so that a hash is never
reported without the tree it came from. The driver refuses to write a manifest
whose files were not all built from the same tree.

The split is deliberate: it keeps a co-signer from having to choose between
signing bytes they could not verify and withholding a signature from the whole
release.

# Co-signing the release manifest

Co-maintainers and contributors wishing to add their own signature rebuild the
release and compare it against the captain's manifest. Hand the manifest to the
driver and it does the rest:

```shell
tools/reprobuild verify SHA256SUMS-<version>
```

It takes the commit and the timestamp **from the manifest**, not from whatever
you have checked out — so you need that commit in your clone, but not on your
current branch — rebuilds every file the manifest lists, compares them, and
writes `SHA256SUMS-<version>.asc.<keyid>` only if all of them matched. Send
that signature to the release captain, who merges it with the others.

If the driver tells you that commit is not in your clone, fetch the tag first.
For an ordinary release it is on GitHub:

```shell
git fetch origin tag v<version>
```

For an **embargoed** release the tag is only on the project's private mirror
until disclosure, so fetch it from there instead — ask the release captain for
the remote if you do not have it:

```shell
git fetch <private-mirror> tag v<version>
```

You do not need to check the tag out: `verify` builds the commit the manifest
names, wherever your working tree happens to be.

Lines for image digests are reported but never block: building the images is
optional for a co-signer.

If a file differs, the driver prints both hashes and withholds the signature.
That is the whole protocol: tell the captain what you got, and the two of you
work out the cause before anything is published.

For the second manifest, run the same command against it. If it does not match,
do not sign it — report the hashes you got and move on. That is a
known-possible outcome today, and withholding the signature is the correct
response, not a reason to hold up the release.

Because one tarball now covers every distribution for its architecture, a co-signer
with an x86-64 machine can reproduce **all three** rows: the arm rows are
cross-compiled, so no ARM hardware is needed.

> **Caveat: the `armhf` row is not currently reproducible across machines.**
>
> The `amd64` and `arm64` artifacts have been confirmed byte-identical when
> built on two different x86-64 machines — different CPU vendors, different
> core counts, different kernels, one with host Nix and one through the
> pinned container. The `armhf` artifacts have not: two machines produce two
> different hashes, stably, for `clightning-<version>-static-armhf.tar.xz`.
>
> This is a build-toolchain defect, not something about your machine: the
> build inputs carry identical content hashes on both ends, each machine
> reproduces its *own* output exactly (`--rebuild` passes everywhere), and
> the difference is confined to the 32-bit ARM Rust binaries — every C
> binary is byte-identical, build-ids included. The differing bytes are a
> reordered string table in the ARM exception-unwinding objects that Rust
> links in, with the rest following from the strings having moved.
>
> **What this means in practice:** the `armhf` files live in their own
> `SHA256SUMS-<version>-armhf` manifest precisely so that this stays a local
> problem. A mismatch there, with the main manifest passing, is currently
> expected and is *not* evidence of a tampered artifact: report the hashes you
> got, withhold your signature on the `armhf` manifest, and sign the main one
> as normal. The 32-bit ARM binaries are still built, published and signed by
> the captain; what they may lack is *independent* confirmation.
>
> Concretely, this means the `armhf` artifacts can carry a weaker guarantee
> than the rest of the release — captain-attested rather than
> multi-party-reproduced — and you should weigh that as you would any
> single-source binary. The `amd64` and `arm64` artifacts are unaffected.
>
> The same applies to the `linux/arm/v7` half of the Docker images, and by
> extension to the multi-arch image index, whose digest is computed over all
> three architectures and so cannot be reproduced independently either. The
> `linux/amd64` and `linux/arm64` image digests can be, and are signed in the
> main manifest. A single 3-arch image is still published, so `docker pull`
> is unchanged whichever architecture you are on.

# Verifying a reproducible build

You can verify the reproducible build in two ways:

- Repeating the entire reproducible build, making sure from scratch that the binaries match. Just follow the instructions above for this.
- Verifying that the downloaded binaries match the hashes in `SHA256SUMS-<version>` and that the signatures in `SHA256SUMS-<version>.asc` are valid.

Assuming you have downloaded the binaries, the manifest and the signatures into the same directory, you can verify the signatures with the following:

```shell
gpg --verify SHA256SUMS-<version>.asc SHA256SUMS-<version>
```

Pass both filenames explicitly. With a single argument `gpg` picks its verification mode from the packet structure of the `.asc` file: for a genuine detached signature it guesses the sibling `SHA256SUMS`, but for an inline (clear-signed or embedded) message it verifies only the payload carried inside the `.asc` itself. It never reads `SHA256SUMS` in that case, and although it prints `WARNING: not a detached signature; file 'SHA256SUMS' was NOT verified!`, it still exits with status 0 — so the warning is easy to miss by eye and invisible to any script that only checks the exit code. Naming the manifest as the second argument forces `gpg` to check the signatures against that exact file, and to fail outright if the `.asc` is not a detached signature over it.

And you should see a list of messages like the following:

```shell
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

If there are any issues `gpg` will print `Bad signature`, it might be because the signatures do not match the manifest, and could be the result of a filename change. Do not continue using the binaries, and contact the maintainers, if this is not the case, a failure here means that the verification failed.

Next we verify that the binaries match the ones in the manifest:

```shell
sha256sum -c --ignore-missing SHA256SUMS-<version>
```

Producing output similar to the following:

```shell
clightning-v25.12-static-amd64.tar.xz: OK
clightning-v25.12-static-arm64.tar.xz: OK
clightning-v25.12.zip: OK
```

`--ignore-missing` is there because the manifest lists every file in the
release and you have probably downloaded only the ones you need — including the
source archive, which is listed from the start but only published later for an
embargoed release. Without it, `sha256sum` reports the files you do not have as
failures. A failure to verify the hash would give a warning like the following:

```shell
sha256sum: WARNING: 1 computed checksum did NOT match
```

If both the signature verification and the manifest checksum verification succeeded, then you have just successfully verified a reproducible build and, assuming you trust the maintainers, are good to install and use the binaries. Congratulations! 🎉🥳
