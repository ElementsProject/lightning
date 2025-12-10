#!/bin/bash -eu
# Generate HTML coverage reports for each test
# Usage: ./per-test-coverage-html.sh [PROFDATA_DIR] [OUTPUT_DIR]

PROFDATA_DIR="${1:-coverage/per-test}"
OUTPUT_DIR="${2:-coverage/per-test-html}"

if [ ! -d "$PROFDATA_DIR" ]; then
    echo "ERROR: Profdata directory not found: $PROFDATA_DIR"
    echo "Run ./contrib/coverage/per-test-coverage.sh first"
    exit 1
fi

# Get all binaries from Makefile (includes plugins, tools, test binaries)
echo "Discovering instrumented binaries from Makefile..."
BINARIES=($(make -qp 2>/dev/null | awk '/^ALL_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$'))
TEST_BINARIES=($(make -qp 2>/dev/null | awk '/^ALL_TEST_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$'))

# Combine all binaries
ALL_BINARIES=("${BINARIES[@]}" "${TEST_BINARIES[@]}")

# Build llvm-cov arguments
ARGS=()
for bin in "${ALL_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        if [ ${#ARGS[@]} -eq 0 ]; then
            ARGS+=("$bin")  # First binary is primary
        else
            ARGS+=("-object=$bin")  # Others use -object=
        fi
    fi
done

if [ ${#ARGS[@]} -eq 0 ]; then
    echo "ERROR: No instrumented binaries found"
    echo "Make sure you've built with --enable-coverage"
    exit 1
fi

# Find all profdata files
PROFDATA_FILES=($(find "$PROFDATA_DIR" -name "*.profdata" 2>/dev/null | sort))

if [ ${#PROFDATA_FILES[@]} -eq 0 ]; then
    echo "ERROR: No .profdata files found in $PROFDATA_DIR"
    echo "Run ./contrib/coverage/per-test-coverage.sh first"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Generating HTML reports for ${#PROFDATA_FILES[@]} tests..."
echo "Using ${#ARGS[@]} instrumented binaries"
echo ""

# Generate HTML for each test
for profdata in "${PROFDATA_FILES[@]}"; do
    test_name=$(basename "$profdata" .profdata)
    html_dir="$OUTPUT_DIR/$test_name"

    echo -n "  $test_name... "

    # Generate HTML report
    if llvm-cov show "${ARGS[@]}" \
        -instr-profile="$profdata" \
        -format=html \
        -output-dir="$html_dir" \
        -show-line-counts-or-regions \
        -show-instantiations=false 2>/dev/null; then
        echo "✓"
    else
        echo "✗ (failed)"
        rm -rf "$html_dir"
    fi
done

echo ""
echo "HTML reports generated in: $OUTPUT_DIR"
echo ""
echo "Open reports:"
for profdata in "${PROFDATA_FILES[@]}"; do
    test_name=$(basename "$profdata" .profdata)
    html_dir="$OUTPUT_DIR/$test_name"
    if [ -f "$html_dir/index.html" ]; then
        echo "  $test_name: $html_dir/index.html"
    fi
done
