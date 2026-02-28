# Test Coverage

> Coverage isn't everything, but it can tell you were you missed a thing.

We use LLVM's [Source-Based Code Coverage][sbcc] support to instrument
the code at compile time. This instrumentation then emits coverage
files (`profraw`), which can then be aggregated via `llvm-profdata`
into a single `profdata` file, and from there a variety of tools can
be used to inspect coverage.

The most common use is to generate an HTML report for all binaries
under test. CLN being a multi-process system has a number of binaries,
sharing some source code. To simplify the aggregation of data and
generation of the report split per source file, we use the
`prepare-code-coverage-artifact.py` ([`pcca.py`][pcca]) script from
the LLVM project.

## Conventions

The `tests/fixtures.py` sets the `LLVM_PROFILE_FILE` environment
variable, indicating that the `profraw` files ought to be stores in
`coverage/raw`. Processing the file then uses [`pcca.py`][pcca] to
aggregate the raw files, into a data file, and then generate a
per-source-file coverage report.

This report is then published [here][report]

[sbcc]: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
[pcca]: https://github.com/ElementsProject/lightning/tree/master/contrib/prepare-code-coverage-artifact.py
[report]: https://cdecker.github.io/lightning/coverage
