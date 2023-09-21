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
	    --dev-*)
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

# Remove undocumented proprieties, usually these proprieties are
# under experimental phases.
remove_undoc()
{
    # shellcheck disable=SC2162
    while read OPT; do
	grep -q "^$OPT$" < doc/undoc-flags.list || echo "$OPT"
    done
}

# If we don't get any, we failed!
CMD_OPTNAMES=$(get_cmd_opts "$1" | sort | remove_undoc)
if [ -z "$CMD_OPTNAMES" ]; then
    echo "Failed to get options from $0!" >&2
    exit 1
fi

# Now, gather (long) opt names from man page, make sure they match.
MAN_OPTNAMES=$(grep -vi 'deprecated in' "$2" | sed -E -n 's,^\* \*\*(--)?([^*/]*)\*\*(/\*\*-.\*\*)?(=?).*,\2\4,p'| sort)

if [ "$CMD_OPTNAMES" != "$MAN_OPTNAMES" ]; then
    echo "diff of command names vs manpage names":
    diff -u --label="$1" <(echo "$CMD_OPTNAMES") --label="$2" <(echo "$MAN_OPTNAMES")
    exit 2
fi
