#!/usr/bin/env bash

if ! diff -u <(grep -E 'sudo apt-get install .*git' README.md) \
     <(grep -E 'sudo apt-get install .*git' doc/INSTALL.md); then
    echo "Dependencies listed in README.md are not identical to those listed in doc/INSTALL.md (see above). Please fix."
    exit 1
fi
