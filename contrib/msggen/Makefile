#! /usr/bin/make

contrib/msggen/msggen/schema.json: ${SCHEMAS}
	PYTHONPATH=contrib/msggen ${PYTHON} contrib/msggen/msggen/__main__.py bundle doc/schemas
