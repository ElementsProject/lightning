#!/bin/bash -eu
# Generate HTML and text coverage reports from merged profile data
# Usage: ./generate-coverage-report.sh [PROFDATA_FILE] [OUTPUT_DIR]

PROFDATA="${1:-coverage/merged.profdata}"
OUTPUT_DIR="${2:-coverage/html}"

if [ ! -f "$PROFDATA" ]; then
    echo "ERROR: Profile not found: $PROFDATA"
    echo "Run collect-coverage.sh first to create the merged profile"
    exit 1
fi

# Get all binaries from Makefile (includes plugins, tools, test binaries)
echo "Discovering instrumented binaries from Makefile..."
mapfile -t BINARIES < <(make -qp 2>/dev/null | awk '/^ALL_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$')
mapfile -t TEST_BINARIES < <(make -qp 2>/dev/null | awk '/^ALL_TEST_PROGRAMS :=/ {$1=$2=""; print}' | tr ' ' '\n' | grep -v '^$')

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

echo "Generating coverage report for ${#ARGS[@]} binaries..."

# Generate HTML report
llvm-cov show "${ARGS[@]}" \
    -instr-profile="$PROFDATA" \
    -format=html \
    -output-dir="$OUTPUT_DIR" \
    -show-line-counts-or-regions \
    -show-instantiations=false

echo "✓ HTML report: $OUTPUT_DIR/index.html"

# Generate text summary
mkdir -p coverage
llvm-cov report "${ARGS[@]}" \
    -instr-profile="$PROFDATA" \
    | tee coverage/summary.txt

echo "✓ Summary: coverage/summary.txt"
