#!/usr/bin/env bash

if [ $# -eq 0 ]; then
    # With no args, read stdin to scrape compiler output.
    # shellcheck disable=SC2046
    set -- $(while read -r LINE; do
	case "$LINE" in
	    *undefined\ reference\ to*)
		LINE=${LINE#*undefined reference to \`}
		echo "${LINE%\'*}"
		;;
	    *)
		continue
		;;
	esac; done | sort -u)
fi

for SYMBOL; do
    # If there are multiple declarations, pick first (eg. common/memleak.h
    # has notleak_ as a declaration, and then an inline).
    WHERE=$(grep -nH "^[a-zA-Z0-9_ (),]* [*]*$SYMBOL(" ./*/*.h | head -n1)
    if [ x"$WHERE" != x ]; then
	STUB='\n{ fprintf(stderr, "'$SYMBOL' called!\\n"); abort(); }'
    else
	echo "/* Could not find declaration for $SYMBOL */"
	continue
    fi

    echo "/* Generated stub for $SYMBOL */"
    FILE=${WHERE%%:*}
    FILE_AND_LINE=${WHERE%:*}
    LINE=${FILE_AND_LINE#*:}
    END=$(tail -n "+${LINE}" < "$FILE" | grep -n ';$');
    NUM=${END%%:*}

    tail -n "+${LINE}" < "$FILE" | head -n "$NUM" | sed 's/^extern *//' | sed 's/PRINTF_FMT([^)]*)//' | sed 's/NORETURN//g' | sed 's/,/ UNNEEDED,/g' | sed 's/\([a-z0-9A-Z*_]* [a-z0-9A-Z*_]*\));/\1 UNNEEDED);/' | sed "s/;\$/$STUB/" | sed 's/\s*$//'
done
