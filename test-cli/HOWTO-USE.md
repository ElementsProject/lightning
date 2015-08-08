You can see my example test scripts `test-cli/scripts/setup.sh` and
`test-cli/scripts/test.sh`.  They are designed to be run from the `test-cli`
directory.

These are set up for Elements alpha; if you want to use bitcoind (and
thus NOPs instead of OP_CHECKLOCKTIMEVERIFY and
OP_CHECKSEQUENCEVERIFY, as well as being vulnerable to malleability)
you can change the "FEATURES :=" line in `Makefile` (and `make clean`)

You can see other settings in `test-cli/scripts/vars.sh`.

As the utilities un test-cli don't keep any state, and don't talk to
bitcoind/alphad, the commandlines get ugly fast (and don't handle all
cases).  They're only for testing.

Good luck!

Rusty.
