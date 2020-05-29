#!/usr/bin/env bash

if [ $# -eq 0 ]; then
    # With no args, read stdin to scrape compiler output.
    # shellcheck disable=SC2046
    set -- $(while read -r LINE; do
	case "$LINE" in
	    *undefined\ reference\ to*)
		# file.cc:(.text+0x10): undefined reference to `foo()'
		LINE=${LINE#*undefined reference to \`}
		echo "${LINE%\'*}"
		;;
	    *undefined\ symbol:*)
		# ld: error: undefined symbol: foo()
		echo "${LINE#*undefined symbol: }"
		;;
	    *,\ referenced\ from:*)
		# Apple clang version 11.0.3 (clang-1103.0.32.29)
                # "_towire", referenced from:
		LINE=${LINE#\"_}
		echo "${LINE%\"*}"
		;;
	    *)
		continue
		;;
	esac; done | LC_ALL=C sort -u)
fi

for SYMBOL; do
    # If there are multiple declarations, pick first (eg. common/memleak.h
    # has notleak_ as a declaration, and then an inline).
    WHERE=$(grep -nH "^[a-zA-Z0-9_ (),]* [*]*$SYMBOL(" ./*/*.h | head -n1)
    if [ x"$WHERE" = x ]; then
	echo "/* Could not find declaration for $SYMBOL */"
	continue
    fi

    FILE=${WHERE%%:*}
    FILE_AND_LINE=${WHERE%:*}
    LINE=${FILE_AND_LINE#*:}
    END=$(tail -n "+${LINE}" < "$FILE" | grep -n ';$');
    NUM=${END%%:*}

    if grep -q "$SYMBOL.*mock empty" "$FILE"; then
	STUB="{ }"
    else
	# \n on RHS is a GNU extension, and we want to work on FreeBSD
	# shellcheck disable=SC1004
	STUB='\
{ fprintf(stderr, "'$SYMBOL' called!\\n"); abort(); }'
    fi

    echo "/* Generated stub for $SYMBOL */"

    tail -n "+${LINE}" < "$FILE" | head -n "$NUM" | sed 's/^extern *//' | sed 's/PRINTF_FMT([^)]*)//' | sed 's/NON_NULL_ARGS([^)]*)//' | sed 's/NO_NULL_ARGS//g' | sed 's/NORETURN//g' | sed 's/LAST_ARG_NULL//g' | sed 's/WARN_UNUSED_RESULT//g' | sed 's/,/ UNNEEDED,/g' | sed 's/\([a-z0-9A-Z*_]* [a-z0-9A-Z*_]*\));/\1 UNNEEDED);/' | sed "s/;\$/$STUB/" | sed 's/[[:space:]]*$//'
done
