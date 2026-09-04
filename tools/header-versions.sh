#!/bin/sh
set -e -o pipefail

if [ "$#" -ne 1 ] ; then
	echo "Usage: $0 <versionheader>" >&2
	exit 1
fi

unset file
if [ -f "$1" ] ; then
	exec <"$1"
	flock 0
	file="$(cat)"
fi

have_sqlite3() { [ "${HAVE_SQLITE3:-0}" -ne 0 ] ; }
if have_sqlite3 ; then
	SQLITE_VERSION_NUMBER=$({
			${CC:-cc} ${SQLITE3_CFLAGS} -E -o - - <<-END
				#include <sqlite3.h>
				SQLITE_VERSION_NUMBER
			END
		} | tail -n1)
fi

new=$(
	echo "/* Generated file by $0, do not edit! */"
	have_sqlite3 && echo "/* SQLITE3 version: ${SQLITE_VERSION_NUMBER} */"
	echo '#include <ccan/err/err.h>'
	have_sqlite3 && echo '#include <sqlite3.h>'
	echo
	echo 'static inline void check_linked_library_versions(void)'
	echo '{'
	have_sqlite3 && printf '%s\n' \
	'       /* Require at least the version we compiled with. */' \
	'	if (SQLITE_VERSION_NUMBER > sqlite3_libversion_number())' \
	'		errx(1, "SQLITE version mismatch: compiled %u, now %u",' \
	'		     SQLITE_VERSION_NUMBER, sqlite3_libversion_number());' \
	'       /* Ensure the major version matches. */' \
	'	if (SQLITE_VERSION_NUMBER + 1000000 < sqlite3_libversion_number())' \
	'		errx(1, "SQLITE major version mismatch: compiled %u, now %u",' \
	'		     SQLITE_VERSION_NUMBER, sqlite3_libversion_number());' \
	'	/* Earliest supported sqlite3 version */' \
	'	if (SQLITE_VERSION_NUMBER < 3026000)' \
	'		errx(1, "SQLITE version %u too old (minimum 3.26)",' \
	'		     SQLITE_VERSION_NUMBER);'
	echo '}'
)

[ "${new}" = "${file}" ] || echo "${new}" >"$1"
