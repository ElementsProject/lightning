#!/usr/bin/env bash
# Needs bash for process substitition, ie <(

if [ $# != 2 ]; then
    echo "Usage $0 <command> <markdown.md>" >&2
    exit 1
fi

get_cmd_opts()
{
    # Trim out -- after first one (--option mentioned in help!)
    $1 --help | grep '^-' | sed 's/[ 	].*--.*//' | while IFS=$'\n' read -r opt; do
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

CMD_OPTNAMES=$(get_cmd_opts "$1" | sort)

# Now, gather (long) opt names from man page, make sure they match.
MAN_OPTNAMES=$(sed -E -n 's/^ \*\*(--)?([^*/]*)\*\*(=?).*/\2\3/p' < "$2" | sort)

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
    diff -u <(echo "$CMD_OPTNAMES") <(echo "$MAN_OPTNAMES")
    exit 2
fi
