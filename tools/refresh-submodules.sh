#! /bin/sh

if [ $# = 0 ]; then
    echo "Usage: $0 <submoduledir1>..." >&2
    exit 1
fi

# If no git dir (or, if we're a submodule, git file), forget it.
[ -e .git ] || exit 0

# git submodule can't run in parallel.  Really.
# Wait for it to finish if in parallel.
if ! mkdir .refresh-submodules 2>/dev/null ; then
    # If we don't make progress in ~60 seconds, force delete and retry.
    LIMIT=$((50 + $$ % 20))
    i=0
    while [ $i -lt $LIMIT ]; do
	[ -d .refresh-submodules ] || exit 0
	sleep 1
	i=$((i + 1))
    done
    rmdir .refresh-submodules
    exec "$0" "$@" || exit 1
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
    git submodule update --init --recursive "$@"
fi
