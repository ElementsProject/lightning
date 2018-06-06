#! /bin/sh

if [ $# = 0 ]; then
    echo "Usage: $0 <submoduledir1>..." >&2
    exit 1
fi

# git submodule can't run in parallel.  Really.
echo $$ > .refresh-submodules.$$
if ! mv -n .refresh-submodules.$$ .refresh-submodules; then
    rm -f .refresh-submodules.$$
    exit 0
fi
trap "rm -f .refresh-submodules" EXIT

# Be a little careful here, since we do rm -rf!
for m in "$@"; do
    if ! grep -q "path = $m\$" .gitmodules; then
	echo "$m is not a submodule!" >&2
	exit 1
    fi
done

# git submodule can segfault.  Really.
if [ "$(git submodule status "$@" | grep -c '^ ')" != $# ]; then
    echo Reinitializing submodules "$@" ...
    git submodule sync "$@"
    rm -rf "$@"
    git submodule update --init "$@"
fi
