#! /bin/sh

# If this file exists, we send that message back, then sleep.
if [ "$1" != "--version" ] && [ -f openingd-version ]; then
    # lightningd expects us to write to stdin!
    cat openingd-version >&0
    sleep 10
    exit 0
fi

exec "$(cat openingd-real)" "$@"
