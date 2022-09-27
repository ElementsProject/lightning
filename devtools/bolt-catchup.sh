#! /bin/sh
# A script to upgrade spec versions one at a time, stop when something changes.

set -e
BOLTDIR=${1:-../bolts}

HEAD=$(git -C "$BOLTDIR" show --format=%H -s)
VERSION=$(sed -n 's/^DEFAULT_BOLTVERSION[ ]*:=[ ]*\([0-9a-f]*\)/\1/p' < Makefile)

# We only change Makefile at exit, otherwise git diff shows the difference, of course!
finalize_and_exit()
{
    sed "s/^DEFAULT_BOLTVERSION[ ]*:=[ ]*\([0-9a-f]*\)/DEFAULT_BOLTVERSION := $v/" < Makefile > Makefile.$$ && mv Makefile.$$ Makefile
    exit 0
}

for v in $(git -C "$BOLTDIR" show "$VERSION..$HEAD" --format=%H -s | tac); do
    echo "Trying $v..."
    make -s extract-bolt-csv DEFAULT_BOLTVERSION="$v" || finalize_and_exit
    git diff --exit-code || finalize_and_exit
    make -s check-source-bolt DEFAULT_BOLTVERSION="$v" || finalize_and_exit
done

echo "No changes, simply upgrading to $v..."
finalize_and_exit
