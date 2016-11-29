#! /bin/sh

if [ $# -eq 0 ]; then
    # With no args, read stdin to scrape compiler output.
    set -- $(while read LINE; do
	case "$LINE" in
	    *undefined\ reference\ to*)
		LINE=${LINE#*undefined reference to \`}
		echo ${LINE%\'*}
		;;
	    *)
		continue
		;;
	esac; done | sort -u)
fi

for SYMBOL; do
    WHERE=$(grep -nH "^[a-z0-9_ ]* [*]*$SYMBOL(" daemon/*.h)
    if [ x"$WHERE" != x ]; then
	STUB='\n{ fprintf(stderr, "'$SYMBOL' called!\\n"); abort(); }'
    else
	WHERE=$(grep -nH "^extern \(const \)\?struct [a-zA-Z0-9_]* $SYMBOL;$" daemon/*.h)
	if [ x"$WHERE" != x ]; then
	    STUB=';'
	else
	    echo "/* Could not find declaration for $SYMBOL */"
	    continue
	fi
    fi
	
    echo "/* Generated stub for $SYMBOL */"
    FILE=${WHERE%%:*}
    FILE_AND_LINE=${WHERE%:*}
    LINE=${FILE_AND_LINE#*:}
    END=$(tail -n +$LINE < $FILE | grep -n ';$');
    NUM=${END%%:*}

    tail -n +$LINE < $FILE | head -n $NUM | sed 's/^extern *//' | sed 's/PRINTF_FMT([^)]*)//' | sed 's/,/ UNNEEDED,/g' | sed 's/\([a-z0-9A-Z*_]* [a-z0-9A-Z*_]*\));/\1 UNNEEDED);/' | sed "s/;\$/$STUB/" | sed 's/\s*$//'
done
