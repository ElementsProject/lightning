#!/usr/bin/env bash

if git --no-pager grep -nHiE 'l[ightn]{6}g|l[ightn]{8}g|ilghtning|lgihtning|lihgtning|ligthning|lighnting|lightinng|lightnnig|lightnign' -- . ':!tools/check-spelling.sh' ':!tests/data/routing_gossip_store' | grep -vE "highlighting|LightningGrpc"; then
    echo "Identified a likely misspelling of the word \"lightning\" (see above). Please fix."
    echo "Is this warning incorrect? Please teach tools/check-spelling.sh about the exciting new word."
    exit 1
fi

if git --no-pager grep -nHiEP '(?<!en)ctlv' -- . ':!tools/check-spelling.sh'; then
    echo "It's check lock time verify, not check time lock verify!" >&2
    exit 1
fi
