#!/bin/bash -eu
# Merge all .profraw files into a single .profdata file
# Usage: ./collect-coverage.sh [COVERAGE_DIR] [OUTPUT_FILE]

COVERAGE_DIR="${1:-${CLN_COVERAGE_DIR:-/tmp/cln-coverage}}"
OUTPUT="${2:-coverage/merged.profdata}"

echo "Collecting coverage from: $COVERAGE_DIR"

# Find all profraw files
mapfile -t PROFRAW_FILES < <(find "$COVERAGE_DIR" -name "*.profraw" 2>/dev/null || true)

if [ ${#PROFRAW_FILES[@]} -eq 0 ]; then
    echo "ERROR: No .profraw files found in $COVERAGE_DIR"
    exit 1
fi

echo "Found ${#PROFRAW_FILES[@]} profile files"

# Validate each profraw file and filter out corrupt/incomplete ones
# Define validation function for parallel execution
validate_file() {
    local profraw="$1"

    # Check if file is empty
    if [ ! -s "$profraw" ]; then
        return 1  # Empty
    fi

    # Check if file is suspiciously small (likely incomplete write)
    # Valid profraw files are typically > 1KB
    filesize=$(stat -c%s "$profraw" 2>/dev/null || stat -f%z "$profraw" 2>/dev/null)
    if [ "$filesize" -lt 1024 ]; then
        return 2  # Too small
    fi

    # Try to validate the file by checking if llvm-profdata can read it
    if llvm-profdata show "$profraw" >/dev/null 2>&1; then
        echo "$profraw"  # Valid - output to stdout
        return 0
    else
        return 3  # Corrupt
    fi
}

# Export function for parallel execution
export -f validate_file

TOTAL=${#PROFRAW_FILES[@]}
NPROC=$(nproc 2>/dev/null || echo 4)
echo "Validating ${TOTAL} files in parallel (using ${NPROC} cores)..."

# Run validation in parallel and collect valid files
mapfile -t VALID_FILES < <(
    printf '%s\n' "${PROFRAW_FILES[@]}" | \
    xargs -P "$NPROC" -I {} bash -c 'validate_file "$@"' _ {}
)

# Calculate error counts
CORRUPT_COUNT=$((TOTAL - ${#VALID_FILES[@]}))

if [ ${#VALID_FILES[@]} -eq 0 ]; then
    echo "ERROR: No valid .profraw files found (all $CORRUPT_COUNT files were corrupt/incomplete)"
    exit 1
fi

echo "Valid files: ${#VALID_FILES[@]}"
if [ $CORRUPT_COUNT -gt 0 ]; then
    echo "Filtered out: $CORRUPT_COUNT files (empty/small/corrupt)"
fi
mkdir -p "$(dirname "$OUTPUT")"

# Merge with -sparse flag for efficiency
# Use batched merging to avoid "Argument list too long" errors
BATCH_SIZE=500
TOTAL_FILES=${#VALID_FILES[@]}

if [ "$TOTAL_FILES" -le "$BATCH_SIZE" ]; then
    # Small enough to merge in one go
    echo "Merging ${TOTAL_FILES} files..."
    llvm-profdata merge -sparse "${VALID_FILES[@]}" -o "$OUTPUT"
else
    # Need to merge in batches
    echo "Merging ${TOTAL_FILES} files in batches of ${BATCH_SIZE}..."

    # Create temp directory for intermediate files
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/profdata-merge.XXXXXX")
    trap 'rm -rf "$TEMP_DIR"' EXIT

    BATCH_NUM=0
    INTERMEDIATE_FILES=()

    # Merge files in batches
    for ((i=0; i<TOTAL_FILES; i+=BATCH_SIZE)); do
        BATCH_NUM=$((BATCH_NUM + 1))
        END=$((i + BATCH_SIZE))
        if [ "$END" -gt "$TOTAL_FILES" ]; then
            END=$TOTAL_FILES
        fi

        BATCH_FILES=("${VALID_FILES[@]:$i:$BATCH_SIZE}")
        INTERMEDIATE="$TEMP_DIR/batch-$BATCH_NUM.profdata"

        echo "  Batch $BATCH_NUM: merging files $((i+1))-$END..."
        llvm-profdata merge -sparse "${BATCH_FILES[@]}" -o "$INTERMEDIATE"
        INTERMEDIATE_FILES+=("$INTERMEDIATE")
    done

    # Merge all intermediate files into final output
    echo "Merging ${#INTERMEDIATE_FILES[@]} intermediate files into final output..."
    llvm-profdata merge -sparse "${INTERMEDIATE_FILES[@]}" -o "$OUTPUT"

    # Cleanup handled by trap
fi

echo "✓ Merged profile: $OUTPUT"
