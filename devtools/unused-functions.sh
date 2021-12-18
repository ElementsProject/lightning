#! /bin/sh

# Files to look inside: don't count test files.  We don't use git grep
# because we want to find occurences in wiregen files.
FILES=$(find ./* -name '*.[ch]' | grep -v /test/run- | grep -v ^./ccan/ | grep -v ^./external/ | grep -v ^./tests/)

if [ $# = 0 ]; then
    HEADERS=$(echo [a-z]*/*.h)
else
    HEADERS="$*"
fi

for hfile in $HEADERS; do
    # Don't worry about wiregen unused functions.
    if [ "${hfile%_wiregen.h}" != "${hfile}" ]; then
	continue
    fi
    # shellcheck disable=SC2010 disable=SC2086
    USING=$(ls $FILES | grep -v "^./${hfile%.h}\.")
    funcs=$(sed -n 's/^[^#].* \**\([a-z0-9_]*\)(.*/\1/p;s/^\([a-z0-9_]*\)(.*/\1/p' < "$hfile")
    for f in $funcs; do
	# Ignore C and H files both: don't use git grep since we want to find
	# occurrences in generated files too.
	# echo Looking through $(echo $FILES | grep -v "^${hfile%.h}\.")
	# shellcheck disable=SC2086
	if ! grep -qw $f $USING; then
	    echo "$(grep -nHw "$f" "$hfile" | head -n1)": "$f" unused
	fi
    done
done
