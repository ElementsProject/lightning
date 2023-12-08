---
title: "Contributor Workflow"
slug: "contributor-workflow"
excerpt: "Learn the practical process and guidelines for contributing."
hidden: false
createdAt: "2022-12-09T09:57:57.245Z"
updatedAt: "2023-07-12T13:40:58.465Z"
---
## Build and Development

Install the following dependencies for best results:

```shell
sudo apt update
sudo apt install valgrind cppcheck shellcheck libsecp256k1-dev libpq-dev
```

Re-run `configure` and build using `make`:

```shell
./configure
make -j$(nproc)
```

## Debugging

There are various development options enabled by running with `--developer`.  You can log console messages with log_info() in lightningd and status_debug() in other subdaemons.

You can debug crashing subdaemons with the argument `--dev-debugger=channeld`, where `channeld` is the subdaemon name.  It will run `gnome-terminal` by default with a gdb attached to the subdaemon when it starts.  You can change the terminal used by setting the `DEBUG_TERM` environment variable, such as `DEBUG_TERM="xterm -e"` or `DEBUG_TERM="konsole -e"`.

It will also print out (to stderr) the gdb command for manual connection.  The subdaemon will be stopped (it sends itself a `SIGSTOP`); you'll need to `continue` in gdb.

```shell
./configure
make -j$(nproc)
```

## Making BOLT Modifications

All of code for marshalling/unmarshalling BOLT protocol messages is generated directly from the spec. These are pegged to the BOLTVERSION, as specified in `Makefile`.

## Source code analysis

An updated version of the NCC source code analysis tool is available at

<https://github.com/bitonic-cjp/ncc>

It can be used to analyze the lightningd source code by running `make clean && make ncc`. The output (which is built in parallel with the binaries) is stored in .nccout files. You can browse it, for instance, with a command like `nccnav lightningd/lightningd.nccout`.

## Code Coverage

Code coverage can be measured using Clang's source-based instrumentation.

First, build with the instrumentation enabled:

```shell
make clean
./configure --enable-coverage CC=clang
make -j$(nproc)
```

Then run the test for which you want to measure coverage. By default, the raw coverage profile will be written to `./default.profraw`. You can change the output file by setting `LLVM_PROFILE_FILE`:

```shell
LLVM_PROFILE_FILE="full_channel.profraw" ./channeld/test/run-full_channel
```

Finally, generate an HTML report from the profile. We have a script to make this easier:

```shell
./contrib/clang-coverage-report.sh channeld/test/run-full_channel \
    full_channel.profraw full_channel.html
firefox full_channel.html
```

For more advanced report generation options, see the [Clang coverage documentation](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html).

## Subtleties

There are a few subtleties you should be aware of as you modify deeper parts of the code:

- `ccan/structeq`'s STRUCTEQ_DEF will define safe comparison function `foo_eq()` for struct `foo`, failing the build if the structure has implied padding.
- `command_success`, `command_fail`, and `command_fail_detailed` will free the `cmd` you pass in.  
  This also means that if you `tal`-allocated anything from the `cmd`, they will also get freed at those points and will no longer be accessible afterwards.
- When making a structure part of a list, you will instance a `struct list_node`. This has to be the _first_ field of the structure, or else `dev-memleak` command will think your structure has leaked.

## Protocol Modifications

The source tree contains CSV files extracted from the v1.0 BOLT specifications (wire/extracted_peer_wire_csv and wire/extracted_onion_wire_csv).  You can regenerate these by first deleting the local copy(if any) at directory .tmp.bolts, setting `BOLTDIR` and `BOLTVERSION` appropriately, and finally running `make
extract-bolt-csv`. By default the bolts will be retrieved from the directory `../bolts` and a recent git version.

e.g., `make extract-bolt-csv BOLTDIR=../bolts BOLTVERSION=ee76043271f79f45b3392e629fd35e47f1268dc8`
