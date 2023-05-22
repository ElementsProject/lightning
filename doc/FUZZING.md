# Fuzz testing

C-lightning currently supports coverage-guided fuzz testing using [LLVM's libfuzzer](https://www.llvm.org/docs/LibFuzzer.html)
when built with `clang`.

The goal of fuzzing is to generate mutated -and often unexpected- inputs (`seed`s) to pass
to (parts of) a program (`target`) in order to make sure the codepaths used:
- do not crash
- are valid (if combined with sanitizers)
The generated seeds can be stored and form a `corpus`, which we try to optimise (don't
store two seeds that lead to the same codepath).

For more info about fuzzing see [here](https://github.com/google/fuzzing/tree/master/docs),
and for more about `libfuzzer` in particular see [here](https://www.llvm.org/docs/LibFuzzer.html).


## Build the fuzz targets

In order to build the C-lightning binaries with code coverage you will need a recent
[clang](http://clang.llvm.org/). The more recent the compiler version the better.

Then you'll need to enable support at configuration time. You likely want to enable
a few sanitizers for bug detections as well as experimental features for an extended
coverage (not required though).

```
./configure --enable-developer --enable-address-sanitizer --enable-ub-sanitizer --enable-fuzzing --disable-valgrind CC=clang && make
```

The targets will be built in `tests/fuzz/` as `fuzz-` binaries, with their best
known seed corpora stored in `tests/fuzz/corpora/`.

You can run the fuzz targets on their seed corpora to check for regressions:

```
make check-fuzz
```


## Run one or more target(s)

You can run each target independently. Pass `-help=1` to see available options, for
example:
```
./tests/fuzz/fuzz-addr -help=1
```

Otherwise, you can use the Python runner to either run the targets against a given seed
corpus:
```
./tests/fuzz/run.py fuzz_corpus -j2
```
Or extend this corpus:
```
./tests/fuzz/run.py fuzz_corpus -j2 --generate --runs 12345
```

The latter will run all targets two by two `12345` times.

If you want to contribute new seeds, be sure to merge your corpus with the main one:
```
./tests/fuzz/run.py my_locally_extended_fuzz_corpus -j2 --generate --runs 12345
./tests/fuzz/run.py tests/fuzz/corpora --merge_dir my_locally_extended_fuzz_corpus
```


## Improve seed corpora

If you find coverage increasing inputs while fuzzing, please create a pull
request to add them into `tests/fuzz/corpora`. Be sure to minimize any additions
to the corpora first.

### Example

Here's an example workflow to contribute new inputs for the `fuzz-addr` target.

Create a directory for newly found corpus inputs and begin fuzzing:

```shell
mkdir -p local_corpora/fuzz-addr
./tests/fuzz/fuzz-addr -jobs=4 local_corpora/fuzz-addr tests/fuzz/corpora/fuzz-addr/
```

After some time, libFuzzer may find some potential coverage increasing inputs
and save them in `local_corpora/fuzz-addr`. We can then merge them into the seed
corpora in `tests/fuzz/corpora`:

```shell
./tests/fuzz/run.py tests/fuzz/corpora --merge_dir local_corpora
```

This will copy over any inputs that improve the coverage of the existing corpus.
If any new inputs were added, create a pull request to improve the upstream seed
corpus:

```shell
git add tests/fuzz/corpora/fuzz-addr/*
git commit
...
```


## Write new fuzzing targets

In order to write a new target:
 - include the `libfuzz.h` header
 - fill two functions: `init()` for static stuff and `run()` which will be called
     repeatedly with mutated data.
 - read about [what makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

A simple example is [`fuzz-addr`][fuzz-addr]. It setups the
chainparams and context (wally, tmpctx, ..) in `init()` then
bruteforces the bech32 encoder in `run()`.

[fuzz-addr]: https://github.com/ElementsProject/lightning/blob/master/tests/fuzz/fuzz-addr.c
