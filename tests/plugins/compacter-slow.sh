#! /bin/sh -e
# This pretends to be lightning_gossip_compactd, but waits until the file "compactd-continue"
# exists.  This lets us test race conditions.

if [ x"$1" != x"--version" ]; then
    while [ ! -f "compactd-continue" ]; do
	sleep 1
    done
fi

exec "$(dirname "$0")"/../../lightningd/lightning_gossip_compactd "$@"
