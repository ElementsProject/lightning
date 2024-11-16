#!/bin/bash -eu

# Runs each fuzz target on its seed corpus and prints any failures.
FUZZ_DIR=$(dirname "$0")
readonly FUZZ_DIR
TARGETS=$(find "${FUZZ_DIR}" -type f -name "fuzz-*" ! -name "*.*")
readonly TARGETS

export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

passes=0
fails=0
for t in ${TARGETS}; do
	target_name=$(basename "${t}")
	corpus_dir="${FUZZ_DIR}/corpora/${target_name}/"
	cmd="${t} -runs=0 ${corpus_dir}"

	echo -n "Checking ${target_name}... "
	if output=$(${cmd} 2>&1); then
		echo "PASS"
		passes=$((passes + 1))
	else
		echo "FAIL"
		echo
		echo "Failing command: ${cmd}"
		echo "Output:"
		echo "${output}"
		echo
		fails=$((fails + 1))
	fi
done

echo
echo "TOTAL PASSED: ${passes}"
echo "TOTAL FAILED: ${fails}"

exit ${fails}
