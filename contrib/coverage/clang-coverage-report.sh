#!/bin/bash -eu
#
# Generates an HTML coverage report from a raw Clang coverage profile. See
# https://clang.llvm.org/docs/SourceBasedCodeCoverage.html for more details.
# 
# Example usage to create full_channel.html from full_channel.profraw for the
# run-full_channel unit test:
#   ./contrib/clang-coverage-report.sh channeld/test/run-full_channel \
#       full_channel.profraw full_channel.html

if [[ "$#" -ne 3 ]]; then
	echo "Usage: $0 BINARY RAW_PROFILE_FILE TARGET_HTML_FILE"
	exit 1
fi

readonly BINARY="$1"
readonly RAW_PROFILE_FILE="$2"
readonly TARGET_HTML_FILE="$3"

MERGED_PROFILE_FILE=$(mktemp)
readonly MERGED_PROFILE_FILE

llvm-profdata merge -sparse "${RAW_PROFILE_FILE}" -o "${MERGED_PROFILE_FILE}"
llvm-cov show "${BINARY}" -instr-profile="${MERGED_PROFILE_FILE}" -format=html \
	> "${TARGET_HTML_FILE}"

rm "${MERGED_PROFILE_FILE}"
