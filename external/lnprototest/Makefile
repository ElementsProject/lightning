#! /usr/bin/make

PYTHONFILES := $(shell find * -name '*.py')
POSSIBLE_PYTEST_NAMES=pytest-3 pytest3 pytest
PYTEST := $(shell for p in $(POSSIBLE_PYTEST_NAMES); do if type $$p > /dev/null; then echo $$p; break; fi done)
TEST_DIR=tests

default: check-source check check-quotes

check-pytest-found:
	@if [ -z "$(PYTEST)" ]; then echo "Cannot find any pytest: $(POSSIBLE_PYTEST_NAMES)" >&2; exit 1; fi

check: check-pytest-found
	$(PYTEST) $(PYTEST_ARGS) $(TEST_DIR)

check-source: check-fmt check-flake8 check-mypy check-internal-tests

check-flake8:
	flake8 --ignore=E501,E731,W503

check-mypy:
	mypy --ignore-missing-imports --disallow-untyped-defs --disallow-incomplete-defs $(PYTHONFILES)

check-internal-tests: check-pytest-found
	$(PYTEST) `find lnprototest -name '*.py'`

check-quotes/%: %
	tools/check_quotes.py $*

check-quotes: $(PYTHONFILES:%=check-quotes/%)

check-fmt:
	black --check .

fmt:
	black .

TAGS:
	etags `find . -name '*.py'`
