#!/usr/bin/env sh
set -e

MANPAGES=$(ls doc/*.[0-9].txt | sed 's/\.txt$//')
# If there are md manpages not on the readthedoc rst yet
NEW_PAGES="\\n\\n"

for m in $MANPAGES; do
	asciidoc -b docbook "$m.txt"
	pandoc -f docbook -t markdown_strict "$m.xml" -o "$m.md"
	# We don't care about docbook files
	rm "$m.xml"
	grep "$m.md" doc/index.rst || NEW_PAGES="$NEW_PAGES   $(echo "$m".md | sed 's/\//\\\//')\\n"
	cat doc/index.rst
done

if [ ! "$NEW_PAGES" = "\\n\\n" ]; then
	sed -i "s/:caption: Manpages/:caption: Manpages$NEW_PAGES/" doc/index.rst
fi
