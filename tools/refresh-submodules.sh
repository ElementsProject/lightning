#! /bin/sh

if [ $# = 0 ]; then
    echo "Usage: $0 <submoduledir1>..." >&2
    exit 1
fi

# If no git dir, forget it.
[ -d .git ] || exit 0

# git submodule can't run in parallel.  Really.
if ! mkdir .refresh-submodules 2>/dev/null ; then
    exit 0
fi

trap "rmdir .refresh-submodules" EXIT

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
