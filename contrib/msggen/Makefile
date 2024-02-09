#! /usr/bin/make

# Files that `msggen` generates for itself, this does not include the
# artifacts that we will be using `msggen` to generate, but rather all
# the files required to work itself. This is distinct from
# `MSGGEN_GENALL`, which consists only of the files generated using
# `msggen`. `msggen.json` is special, it contains information that must not change, therefore it is not included in `clean` calls.
MSGGEN_GEN_ALL = \
	contrib/msggen/msggen/schema.json

MSGGEN_DATA = \
	.msggen.json

contrib/msggen/msggen/schema.json: ${SCHEMAS}
	PYTHONPATH=contrib/msggen ${PYTHON} contrib/msggen/msggen/__main__.py bundle doc/schemas
