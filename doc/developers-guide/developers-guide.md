---
title: "Setting up a dev environment"
slug: "developers-guide"
excerpt: "Get up and running in your local environment with essential tools and libraries in your preferred programming language."
hidden: false
createdAt: "2022-11-18T14:28:23.407Z"
updatedAt: "2023-02-08T11:42:44.759Z"
---
## Using `startup_regtest.sh`

The Core Lightning project provides a script `startup_regtest.sh` to simulate the Lightning Network in your local dev environment. The script starts up some local nodes with bitcoind, all running on regtest and makes it easier to test things out, by hand.

Navigate to `contrib` in your Core Lightning directory:

```shell
cd contrib
```

Load the script, using `source` so it can set aliases:

```shell
source startup_regtest.sh
```

Start up the nodeset:

```shell
start_ln 3
```

Connect the nodes. The `connect a b` command connects node a to b:

```shell
connect 1 2
```

When you're finished, stop:

```shell
stop_ln
```

Clean up the lightning directories:

```shell
 destroy_ln
```

## Using Polar

[Polar](https://lightningpolar.com/) offers a one-click setup of Lightning Network for local app development & testing.

## Using Nix

Install [Nix](https://nixos.org/download/)

Update git submodules `git submodule update --init --recursive`.

The entry point is `flake.nix` in the root of the project, where the inputs and outputs are defined.

`nix develop` will create the default shell env with the build and runtime dependencies of the cln package. Then you can call `make` manually and the project will compile as usual.

`nix develop .#rust` will create a shell env for developing rust.

`nix build .?submodules=1` will build the default package (cln).

`nix flake check .?submodules=1` will build the cln and rust packages. Rust tests are run during the build. There are also checks to run cargo audit and nixfmt.

If you have nix installed you can use `nix run "git+https://github.com/hashrelay/lightning?ref=flake&submodules=1#lightningd"` to run lightningd without having to manually clone the repo. This make use of the flake output apps.
