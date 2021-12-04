#!/usr/bin/env bash

EXIT_CODE=0

# Check include guards

HEADER_ID_PREFIX="LIGHTNING_"
HEADER_ID_SUFFIX="_H"
REGEXP_EXCLUDE_FILES_WITH_PREFIX="ccan/"
for HEADER_FILE in $(git ls-files -- "*.h" | grep -vE "^${REGEXP_EXCLUDE_FILES_WITH_PREFIX}")
do
    HEADER_ID_BASE=$(tr /- _ <<< "${HEADER_FILE/%.h/}" | tr "[:lower:]" "[:upper:]")
    HEADER_ID="${HEADER_ID_PREFIX}${HEADER_ID_BASE}${HEADER_ID_SUFFIX}"
    if [[ $(grep -cE "^#((ifndef|define) ${HEADER_ID}|endif /\\* ${HEADER_ID} \\*/)$" "${HEADER_FILE}") != 3 ]]; then
        echo "${HEADER_FILE} seems to be missing the expected include guard:"
        echo "  #ifndef ${HEADER_ID}"
        echo "  #define ${HEADER_ID}"
        echo "  ..."
        echo "  #endif /* ${HEADER_ID} */"
        echo
        EXIT_CODE=1
    fi
    # Ignore contrib/.
    if [ "${HEADER_FILE##contrib/}" = "$HEADER_FILE" ] && [ "$(grep '#include' "$HEADER_FILE" | head -n1)" != '#include "config.h"' ]; then
	echo "${HEADER_FILE}:1:does not include config.h first"
	EXIT_CODE=1
    fi
done

# Check redundant includes

filter_suffix() {
    git ls-files | grep -v 'ccan/' | grep -E "\\.${1}"'$'
}

for HEADER_FILE in $(filter_suffix h); do
    DUPLICATE_INCLUDES_IN_HEADER_FILE=$(grep -E "^#include " < "${HEADER_FILE}" | sort | uniq -d)
    if [[ ${DUPLICATE_INCLUDES_IN_HEADER_FILE} != "" ]]; then
        echo "Duplicate include(s) in ${HEADER_FILE}:"
        echo "${DUPLICATE_INCLUDES_IN_HEADER_FILE}"
        echo
        EXIT_CODE=1
    fi
    C_FILE=${HEADER_FILE/%\.h/.c}
    if [[ ! -e $C_FILE ]]; then
        continue
    fi
    DUPLICATE_INCLUDES_IN_HEADER_AND_C_FILES=$(grep -hE "^#include " <(sort -u < "${HEADER_FILE}") <(sort -u < "${C_FILE}" | grep -v '"config.h"') | grep -E "^#include " | sort | uniq -d)
    if [[ ${DUPLICATE_INCLUDES_IN_HEADER_AND_C_FILES} != "" ]]; then
        echo "Include(s) from ${HEADER_FILE} duplicated in ${C_FILE}:"
        echo "${DUPLICATE_INCLUDES_IN_HEADER_AND_C_FILES}"
        echo
        EXIT_CODE=1
    fi
done
for C_FILE in $(filter_suffix c); do
    DUPLICATE_INCLUDES_IN_C_FILE=$(grep -E "^#include " < "${C_FILE}" | sort | uniq -d)
    if [[ ${DUPLICATE_INCLUDES_IN_C_FILE} != "" ]]; then
        echo "Duplicate include(s) in ${C_FILE}:"
        echo "${DUPLICATE_INCLUDES_IN_C_FILE}"
        echo
        EXIT_CODE=1
    fi
    H_FILE="${C_FILE%.c}.h"
    H_BASE="$(basename "$H_FILE")"
    if [ -f "$H_FILE" ] && ! grep -E '#include (<'"$H_FILE"'>|"'"$H_BASE"'")' "$C_FILE" > /dev/null; then
	echo "${C_FILE} does not include $H_FILE" >& 2
	EXIT_CODE=1
    fi
    # Ignore contrib/.
    if [ "${C_FILE##contrib/}" = "$C_FILE" ] && [ "$(grep '#include' "$C_FILE" | head -n1)" != '#include "config.h"' ]; then
	echo "${C_FILE}:1:does not include config.h first"
	EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
