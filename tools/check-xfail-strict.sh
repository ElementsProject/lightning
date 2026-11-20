#!/usr/bin/env bash
# Flag a pytest.mark.xfail decorator added under tests/ that does not
# contain strict=True. A decorator split across lines is read until its
# parentheses balance, or until the following def.
#
# Only added lines are checked: see tools/added-lines.sh.
#
# Usage: tools/check-xfail-strict.sh [BASE]

added=$("$(dirname "$0")/added-lines.sh" "${1:-master}" 'tests/*.py') || exit 1
if [ -z "$added" ]; then
	exit 0
fi

hits=$(printf '%s\n' "$added" | cut -d: -f1 | sort -u | while IFS= read -r f; do
	lines=$(printf '%s\n' "$added" | awk -F: -v f="$f" '$1 == f { print $2 }' | tr '\n' ' ')
	awk -v lines="$lines" '
function delta(s,    i, n, c, d, q, sq) {
	d = 0
	q = ""
	sq = sprintf("%c", 39)
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (q != "") {
			if (c == q)
				q = ""
			continue
		}
		if (c == "\"" || c == sq) {
			q = c
			continue
		}
		if (c == "(")
			d++
		else if (c == ")")
			d--
	}
	return d
}

function depth_after_mark(s,    i, rest) {
	i = index(s, "pytest.mark.xfail")
	if (i == 0)
		return 0
	rest = substr(s, i + length("pytest.mark.xfail"))
	sub(/^[[:space:]]*/, "", rest)
	if (substr(rest, 1, 1) != "(")
		return 0
	return delta(rest)
}

BEGIN {
	capturing = 0
	n = split(lines, list, " ")
	for (i = 1; i <= n; i++)
		added[list[i]] = 1
}
{
	if (!capturing) {
		if (index($0, "pytest.mark.xfail") == 0 || !(NR in added))
			next
		block = $0
		start = NR
		depth = depth_after_mark($0)
		if (depth <= 0) {
			if (index(block, "strict=True") == 0)
				printf "%s:%d:pytest.mark.xfail without strict=True\n", FILENAME, start
			next
		}
		capturing = 1
		next
	}
	block = block "\n" $0
	if ($0 ~ /^[[:space:]]*(async[[:space:]]+)?def[[:space:]]/) {
		if (index(block, "strict=True") == 0)
			printf "%s:%d:pytest.mark.xfail without strict=True\n", FILENAME, start
		capturing = 0
		next
	}
	depth += delta($0)
	if (depth <= 0) {
		if (index(block, "strict=True") == 0)
			printf "%s:%d:pytest.mark.xfail without strict=True\n", FILENAME, start
		capturing = 0
	}
}
END {
	if (capturing && index(block, "strict=True") == 0)
		printf "%s:%d:pytest.mark.xfail without strict=True\n", FILENAME, start
}
' "$f"
done)

if [ -n "$hits" ]; then
	printf '%s\n' "$hits"
	exit 1
fi
exit 0
