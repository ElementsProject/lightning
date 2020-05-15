#!/usr/bin/env bash

EXIT_CODE=0
for FILE in $(git grep -lE 'int main\(' | grep -vE '^ccan/' | grep '.c$'); do
	if ! grep -q -e 'setup_locale();' -e 'common_setup(argv\[0\]);' "${FILE}"; then
        echo "main(...) in ${FILE} does not call setup_locale() (see common/utils.h)"
        EXIT_CODE=1
    fi
done
if [[ ${EXIT_CODE} != 0 ]]; then
    echo
    echo "setup_locale() forces the use of the POSIX C locale. By using the"
    echo "POSIX C locale we avoid a class of localization related parsing bugs"
    echo "that can be very tricky to isolate and fix."
fi
exit ${EXIT_CODE}
