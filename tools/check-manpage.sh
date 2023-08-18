#!/usr/bin/env bash
# Needs bash for process substitition, ie <(

if [ $# != 2 ]; then
    echo "Usage $0 <command> <markdown.md>" >&2
    exit 1
fi

get_cmd_opts()
{
    # Trim out -- after first one: ensure width sufficient to give desc
    # on same line, and ignore single-letter prefix e.g. -X|--ex
    COLUMNS=1000 $1 --help | sed -n 's/^\(-.|\)\?\(--[^	]*\)\(  \|	\).*/\2/p' | while IFS=$'\n' read -r opt; do
	case "$opt" in
	    # We don't document dev options.
	    --dev*)
		;;
	    --*=*|--*' <arg>'*)
		echo "${opt%%[ =]*}=" | cut -c3-
		;;
	    --*)
		echo "${opt%%[ 	|]*}" | cut -c3-
		;;
	    -*\|--*)
		opt=${opt##*|}
		echo "${opt%%[ 	|]*}" | cut -c3-
	esac
    done
}

# If we don't get any, we failed!
CMD_OPTNAMES=$(get_cmd_opts "$1" | sort)
if [ -z "$CMD_OPTNAMES" ]; then
    echo "Failed to get options from $0!" >&2
    exit 1
fi

# Now, gather (long) opt names from man page, make sure they match.
MAN_OPTNAMES=$(grep -vi 'deprecated in' "$2" | sed -E -n 's,^\* \*\*(--)?([^*/]*)\*\*(/\*\*-.\*\*)?(=?).*,\2\4,p'| sort)

# Remove undocumented proprieties, usually these proprieties are
# under experimental phases.
for flag in $(jq '.flags[]' <doc/undoc-flags.json) ; do
    # Remove the quotes from the string, so the code will remove
    # the first and last char in the string.
    FLAG=$(sed 's/.//;s/.$//' <(echo "$flag"))
    CMD_OPTNAMES=$(sed "/$FLAG=/d" <(echo "$CMD_OPTNAMES"))
done


if [ "$CMD_OPTNAMES" != "$MAN_OPTNAMES" ]; then
    echo "diff of command names vs manpage names":
    diff -u --label="$1" <(echo "$CMD_OPTNAMES") --label="$2" <(echo "$MAN_OPTNAMES")
    exit 2
fi
