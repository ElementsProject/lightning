#!/usr/bin/make

PKG=client
VERSION := $(shell poetry version -s)

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = docs
BUILDDIR      = build

SDIST_FILE = "dist/pyln-${PKG}-$(VERSION).tar.gz"
BDIST_FILE = "dist/pyln_${PKG}-$(VERSION)-py3-none-any.whl"
ARTEFACTS = $(BDIST_FILE) $(SDIST_FILE)

check: check-source check-pytest

check-source: check-flake8 check-mypy check-version

# We want to create an env for this directory.
check-version:
	poetry env remove -q python3 || true
	poetry env use python3
	poetry install
	[ "`poetry run python3 -c 'from pyln import $(PKG); print($(PKG).__version__)'`" = "$(VERSION)" ] || exit 1

check-flake8:
	flake8 --ignore=E501,E731,W503,E741,E275 pyln tests

check-pytest:
	pytest tests

check-mypy:
#	MYPYPATH=$(PYTHONPATH) mypy --namespace-packages --follow-imports=skip tests pyln

# Having versions in two places sucks, but so does every other option :(
# See https://github.com/python-poetry/poetry/issues/144
upgrade-version:
	if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	poetry version $(NEW_VERSION)
	sed 's/^__version__ = .*/__version__ = "$(NEW_VERSION)"/' < pyln/$(PKG)/__init__.py > pyln/$(PKG)/__init__.py.new && mv pyln/$(PKG)/__init__.py.new pyln/$(PKG)/__init__.py

$(SDIST_FILE) $(BDIST_FILE):
	poetry build

prod-release: check-version $(ARTEFACTS)
	poetry publish
