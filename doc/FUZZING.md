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
DEVELOPER=1 EXPERIMENTAL_FEATURES=1 ASAN=1 UBSAN=1 VALGRIND=0 FUZZING=1 CC=clang ./configure && make
```

The targets will be built in `tests/fuzz/` as `fuzz-` binaries.


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
./tests/fuzz/run.py main_fuzz_corpus --merge_dir my_locally_extended_fuzz_corpus
```


## Write new fuzzing targets

In order to write a new target:
 - include the `libfuzz.h` header
 - fill two functions: `init()` for static stuff and `run()` which will be called
     repeatedly with mutated data.
 - read about [what makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

A simple example is [`fuzz-addr`](tests/fuzz/fuzz-addr.c). It setups the chainparams and
context (wally, tmpctx, ..) in `init()` then bruteforces the bech32 encoder in `run()`.
