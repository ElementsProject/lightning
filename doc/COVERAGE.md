# Code Coverage Guide

This guide explains how to measure code coverage for Core Lightning's test suite.

## Overview

Core Lightning uses Clang's source-based coverage instrumentation to measure which lines of code are executed during tests. This is particularly challenging because:

- CLN is a multi-process application (lightningd + 8 daemon executables)
- Each test spawns multiple nodes, each running multiple daemon processes
- Tests run in parallel (10+ workers)
- Test processes run in temporary directories

Our solution uses `LLVM_PROFILE_FILE` environment variable with unique naming patterns to prevent profile file collisions across parallel processes.

## Local Development Workflow

### Prerequisites

- Clang compiler (clang-15 or later)
- LLVM tools: `llvm-profdata`, `llvm-cov`

Install on Ubuntu/Debian:
```bash
sudo apt-get install clang llvm
```

### Step 1: Build with Coverage Instrumentation

```bash
./configure --enable-coverage CC=clang
make clean  # Important: clean previous builds
make
```

This compiles all binaries with `-fprofile-instr-generate -fcoverage-mapping` flags.

### Step 2: Run Tests with Coverage Collection

Set the coverage directory and run tests:

```bash
export CLN_COVERAGE_DIR=/tmp/cln-coverage
mkdir -p "$CLN_COVERAGE_DIR"
uv run pytest tests/ -n 10
```

You can run a subset of tests for faster iteration:

```bash
uv run pytest tests/test_pay.py -n 10
```

All test processes will write `.profraw` files to `$CLN_COVERAGE_DIR` with unique names like `12345-67890abcdef.profraw` (PID-signature).

### Step 3: Generate Coverage Reports

Merge all profile files and generate HTML report:

```bash
make coverage-clang
```

This runs two scripts:
1. `contrib/coverage/collect-coverage.sh` - Merges all `.profraw` files into `coverage/merged.profdata`
2. `contrib/coverage/generate-coverage-report.sh` - Generates HTML report from merged profile

### Step 4: View the Report

Open the HTML report in your browser:

```bash
xdg-open coverage/html/index.html
```

Or on macOS:

```bash
open coverage/html/index.html
```

The report shows:
- **Per-file coverage**: Which files have been tested
- **Line-by-line coverage**: Which lines were executed and how many times
- **Summary statistics**: Overall coverage percentage

You can also view the text summary:

```bash
cat coverage/summary.txt
```

### Step 5: Clean Up

```bash
make coverage-clang-clean
```

This removes the `coverage/` directory and `$CLN_COVERAGE_DIR`.

## Complete Example

```bash
# Build
./configure --enable-coverage CC=clang
make

# Test
export CLN_COVERAGE_DIR=/tmp/cln-coverage
mkdir -p "$CLN_COVERAGE_DIR"
uv run pytest tests/test_pay.py tests/test_invoice.py -n 10

# Report
make coverage-clang
xdg-open coverage/html/index.html

# Clean
make coverage-clang-clean
```

## Advanced Usage

### Running Specific Test Files

For faster development iteration, run only the tests you're working on:

```bash
uv run pytest tests/test_plugin.py -n 5
```

### Per-Test Coverage

Coverage data is automatically organized by test name, allowing you to see which code each test exercises:

```bash
export CLN_COVERAGE_DIR=/tmp/cln-coverage
mkdir -p "$CLN_COVERAGE_DIR"
uv run pytest tests/test_pay.py tests/test_invoice.py -n 10
```

This creates a directory structure like:
```
/tmp/cln-coverage/
  ├── test_pay/
  │   ├── 12345-abc.profraw
  │   └── 67890-def.profraw
  └── test_invoice/
      ├── 11111-ghi.profraw
      └── 22222-jkl.profraw
```

Generate per-test coverage reports:
```bash
# Generate text summaries
./contrib/coverage/per-test-coverage.sh

# Generate HTML reports (optional)
./contrib/coverage/per-test-coverage-html.sh
```

This creates:
- `coverage/per-test/<test>.profdata` - Merged profile for each test
- `coverage/per-test/<test>.txt` - Text summary for each test
- `coverage/per-test-html/<test>/index.html` - HTML report for each test (if generated)

### Merging Multiple Test Runs

You can accumulate coverage across multiple test runs by reusing the same `CLN_COVERAGE_DIR`:

```bash
export CLN_COVERAGE_DIR=/tmp/cln-coverage
mkdir -p "$CLN_COVERAGE_DIR"

# Run different test subsets
uv run pytest tests/test_pay.py -n 10
uv run pytest tests/test_invoice.py -n 10
uv run pytest tests/test_plugin.py -n 10

# Generate combined report (merges all tests)
make coverage-clang

# Or generate per-test reports
./contrib/coverage/per-test-coverage.sh
```

### Manual Collection and Reporting

If you want more control:

```bash
# Collect and merge
./contrib/coverage/collect-coverage.sh /tmp/cln-coverage coverage/merged.profdata

# Generate report
./contrib/coverage/generate-coverage-report.sh coverage/merged.profdata coverage/html
```

## Continuous Integration

Coverage is automatically measured nightly on the master branch via the `coverage-nightly.yaml` GitHub Actions workflow. The workflow:

1. Builds CLN with coverage instrumentation
2. Runs tests with both sqlite and postgres databases
3. Merges coverage from all test runs
4. Uploads results to Codecov.io
5. Saves HTML reports as artifacts (90-day retention)

You can view:
- **Codecov dashboard**: [codecov.io/gh/ElementsProject/lightning](https://codecov.io/gh/ElementsProject/lightning)
- **HTML artifacts**: Download from GitHub Actions workflow runs

## Troubleshooting

### No .profraw files created

**Problem**: `make coverage-clang` reports "No .profraw files found"

**Solutions**:
1. Verify `CLN_COVERAGE_DIR` is set: `echo $CLN_COVERAGE_DIR`
2. Verify you built with coverage: `./configure --enable-coverage CC=clang && make`
3. Check that tests actually ran successfully

### llvm-profdata not found

**Problem**: `llvm-profdata: command not found`

**Solution**: Install LLVM tools:
```bash
sudo apt-get install llvm
# Or on macOS:
brew install llvm
```

### Binary not found errors in generate-coverage-report.sh

**Problem**: Script complains about missing binaries

**Solution**: Make sure you've run `make` to build all CLN executables

### Coverage shows 0% for some files

**Causes**:
1. Those files weren't executed by your tests (expected)
2. The binary wasn't instrumented (check build flags)
3. The profile data is incomplete

### Corrupt .profraw files

**Problem**: `llvm-profdata merge` fails with "invalid instrumentation profile data (file header is corrupt)"

**Cause**: When test processes crash or timeout, they may leave incomplete/corrupt `.profraw` files.

**Solution**: The `collect-coverage.sh` script automatically validates and filters out bad files:
- **Empty files** - Processes that crash immediately
- **Incomplete files** (< 1KB) - Processes killed before writing enough data
- **Corrupt files** - Files with invalid headers or structure

You'll see output like:
```
Found 1250 profile files
  Skipping empty file: /tmp/cln-coverage/12345-abc.profraw
  Skipping incomplete file (512 bytes): /tmp/cln-coverage/67890-def.profraw
  Skipping corrupt file: /tmp/cln-coverage/11111-ghi.profraw
Valid files: 1247
Filtered out: 3 files
  - Empty: 1
  - Incomplete (< 1KB): 1
  - Corrupt/invalid: 1
✓ Merged profile: coverage/merged.profdata
```

To manually review and clean up corrupt files:
```bash
./contrib/coverage/cleanup-corrupt-profraw.sh
```

This will show you which files are corrupt and offer to delete them.

**Prevention**: Incomplete/corrupt files are unavoidable when tests crash/timeout. The collection script handles this automatically by filtering them out during merge.

## Understanding Coverage Metrics

- **Lines**: Percentage of source code lines executed
- **Functions**: Percentage of functions that were called
- **Regions**: Percentage of code regions (blocks) executed
- **Hit count**: Number of times each line was executed

Aim for:
- **>80% line coverage** for core functionality
- **>60% overall** given the complexity of CLN

Remember: 100% coverage doesn't mean bug-free code, but low coverage means untested code paths.

## References

- [LLVM Source-Based Code Coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)
- [llvm-profdata documentation](https://llvm.org/docs/CommandGuide/llvm-profdata.html)
- [llvm-cov documentation](https://llvm.org/docs/CommandGuide/llvm-cov.html)
