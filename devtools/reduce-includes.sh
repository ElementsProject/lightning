#! /bin/sh -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <cfilepath>...; removes #includes one at a time and checks compile" >&2
    exit 1
fi    

CCMD=$(make show-flags | sed -n 's/CC://p')
for file; do
    i=1
    echo "$file":
    while true; do
	# Don't eliminate config.h includes!
	LINE="$(grep '^#include <' "$file" | grep -v '[<"]config.h[">]' | tail -n +$i | head -n1)"
	[ -n "$LINE" ] || break
	# Make sure even headers end in .c
	grep -F -v "$LINE" "$file" > "$file".c

	if $CCMD /tmp/out.$$.o "$file".c 2>/dev/null; then
	    # shellcheck disable=SC2039
	    echo -n "-$LINE"
	    mv "$file".c "$file"
	else
	    # shellcheck disable=SC2039
	    echo -n "."
	    rm -f "$file".c
	    i=$((i + 1))
	fi
	rm -f /tmp/out.$$.o
    done
    echo
done
