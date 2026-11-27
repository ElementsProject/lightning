#!/usr/bin/env bash
# Print "path:line" for every line the working tree adds since the merge
# base of BASE and HEAD, in files matching the pathspecs.  A check built on
# this complains about new code only, not about what is already there.
#
# Usage: tools/added-lines.sh BASE [pathspec...]

set -o pipefail

base=${1:?usage: added-lines.sh BASE [pathspec...]}
shift

if ! mergebase=$(git merge-base "$base" HEAD 2> /dev/null); then
	echo "added-lines: cannot find a merge base with '$base':" \
	     "set BASE_REF to the branch this work is based on" >&2
	exit 1
fi

# With -U0 a hunk is only removed and added lines; the +++ header is told
# apart from an added line by coming before the first hunk of its file.
git -c core.quotePath=false diff -U0 --no-color --no-ext-diff --no-prefix "$mergebase" -- "$@" | awk '
/^diff --git / { header = 1; next }
header && /^\+\+\+ / { file = substr($0, 5); next }
/^@@ / {
	header = 0
	split($3, range, ",")
	line = substr(range[1], 2) + 0
	next
}
!header && /^\+/ { print file ":" line; line++ }
' || exit 1

# A file git does not know yet is new in every line.
git ls-files --others --exclude-standard -- "$@" | while IFS= read -r file; do
	awk -v file="$file" '{ print file ":" NR }' "$file"
done
