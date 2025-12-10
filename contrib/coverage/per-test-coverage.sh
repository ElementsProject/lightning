#!/bin/bash -eu
# Generate per-test coverage reports
# Usage: ./per-test-coverage.sh [COVERAGE_DIR] [OUTPUT_DIR]

COVERAGE_DIR="${1:-${CLN_COVERAGE_DIR:-/tmp/cln-coverage}}"
OUTPUT_DIR="${2:-coverage/per-test}"

if [ ! -d "$COVERAGE_DIR" ]; then
    echo "ERROR: Coverage directory not found: $COVERAGE_DIR"
    exit 1
fi

# Get all binaries from Makefile (includes plugins, tools, test binaries)
echo "Discovering instrumented binaries from Makefile..."
mapfile -t BINARIES < <(make -qp 2>/dev/null | awk '/^ALL_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$')
mapfile -t TEST_BINARIES < <(make -qp 2>/dev/null | awk '/^ALL_TEST_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$')

# Combine all binaries
ALL_BINARIES=("${BINARIES[@]}" "${TEST_BINARIES[@]}")

# Build llvm-cov arguments
BINARY_ARGS=()
for bin in "${ALL_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        if [ ${#BINARY_ARGS[@]} -eq 0 ]; then
            BINARY_ARGS+=("$bin")  # First binary is primary
        else
            BINARY_ARGS+=("-object=$bin")  # Others use -object=
        fi
    fi
done

if [ ${#BINARY_ARGS[@]} -eq 0 ]; then
    echo "ERROR: No instrumented binaries found"
    echo "Make sure you've built with --enable-coverage"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Find all test subdirectories
mapfile -t TEST_DIRS < <(find "$COVERAGE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)

if [ ${#TEST_DIRS[@]} -eq 0 ]; then
    echo "ERROR: No test subdirectories found in $COVERAGE_DIR"
    echo "Note: Test organization requires CLN_TEST_NAME to be set"
    exit 1
fi

echo "Generating coverage for ${#TEST_DIRS[@]} tests..."

# Process each test
for test_dir in "${TEST_DIRS[@]}"; do
    test_name=$(basename "$test_dir")
    echo -n "  $test_name... "

    # Find profraw files for this test
    mapfile -t PROFRAW_FILES < <(find "$test_dir" -name "*.profraw" 2>/dev/null || true)

    if [ ${#PROFRAW_FILES[@]} -eq 0 ]; then
        echo "no profraw files"
        continue
    fi

    # Validate and filter profraw files
    VALID_FILES=()
    for profraw in "${PROFRAW_FILES[@]}"; do
        if [ -s "$profraw" ]; then
            filesize=$(stat -c%s "$profraw" 2>/dev/null || stat -f%z "$profraw" 2>/dev/null)
            if [ "$filesize" -ge 1024 ]; then
                if llvm-profdata show "$profraw" >/dev/null 2>&1; then
                    VALID_FILES+=("$profraw")
                fi
            fi
        fi
    done

    if [ ${#VALID_FILES[@]} -eq 0 ]; then
        echo "no valid files"
        continue
    fi

    # Merge profraw files for this test
    test_profdata="$OUTPUT_DIR/$test_name.profdata"
    if ! llvm-profdata merge -sparse "${VALID_FILES[@]}" -o "$test_profdata" 2>/dev/null; then
        echo "merge failed"
        continue
    fi

    # Generate text summary for this test
    llvm-cov report "${BINARY_ARGS[@]}" \
        -instr-profile="$test_profdata" \
        > "$OUTPUT_DIR/$test_name.txt" 2>/dev/null || {
        echo "report failed"
        rm -f "$test_profdata"
        continue
    }

    echo "✓ (${#VALID_FILES[@]} files)"
done

echo ""
echo "Per-test coverage reports in: $OUTPUT_DIR"
echo "  - *.profdata - Merged profile data per test"
echo "  - *.txt - Text coverage summary per test"
echo ""
echo "To generate HTML reports for all tests:"
echo "  ./contrib/coverage/per-test-coverage-html.sh"
