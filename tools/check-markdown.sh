#!/bin/bash

diff -u <(egrep 'sudo apt-get install .*git' README.md) \
     <(egrep 'sudo apt-get install .*git' doc/INSTALL.md)
if [[ $? != 0 ]]; then
    echo "Dependencies listed in README.md are not identical to those listed in doc/INSTALL.md (see above). Please fix."
    exit 1
fi
