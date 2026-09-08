#!/bin/bash -eu
# Remove corrupt .profraw files from the coverage directory
# Usage: ./cleanup-corrupt-profraw.sh [COVERAGE_DIR]

COVERAGE_DIR="${1:-${CLN_COVERAGE_DIR:-/tmp/cln-coverage}}"

if [ ! -d "$COVERAGE_DIR" ]; then
    echo "Coverage directory not found: $COVERAGE_DIR"
    exit 1
fi

echo "Scanning for corrupt profraw files in: $COVERAGE_DIR"

# Find all profraw files
mapfile -t PROFRAW_FILES < <(find "$COVERAGE_DIR" -name "*.profraw" 2>/dev/null || true)

if [ ${#PROFRAW_FILES[@]} -eq 0 ]; then
    echo "No .profraw files found"
    exit 0
fi

echo "Found ${#PROFRAW_FILES[@]} profile files"

CORRUPT_FILES=()
for profraw in "${PROFRAW_FILES[@]}"; do
    # Try to validate the file
    if ! llvm-profdata show "$profraw" >/dev/null 2>&1; then
        CORRUPT_FILES+=("$profraw")
    fi
done

if [ ${#CORRUPT_FILES[@]} -eq 0 ]; then
    echo "✓ No corrupt files found"
    exit 0
fi

echo ""
echo "Found ${#CORRUPT_FILES[@]} corrupt file(s):"
for corrupt in "${CORRUPT_FILES[@]}"; do
    echo "  - $corrupt"
done

echo ""
read -p "Delete these corrupt files? [y/N] " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    for corrupt in "${CORRUPT_FILES[@]}"; do
        rm -f "$corrupt"
        echo "  Deleted: $corrupt"
    done
    echo "✓ Removed ${#CORRUPT_FILES[@]} corrupt file(s)"
else
    echo "No files were deleted"
fi
