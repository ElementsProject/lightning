#! /bin/sh -e

. `dirname $0`/vars.sh

$CLI stop
sleep 1 # Make sure socket is closed.
