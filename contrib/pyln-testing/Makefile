#!/usr/bin/make

PKG=testing
VERSION := $(shell grep 'version' pyproject.toml | head -n1 | cut -d'"' -f2)

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
	[ "`uv run python3 -c 'from pyln import $(PKG); print($(PKG).__version__)'`" = "$(VERSION)" ] || exit 1

check-flake8:
	uv run flake8 --ignore=E501,E731,W503,E741  --exclude '*_pb2*.py,grpc2py.py' pyln tests

check-pytest:
	uv run pytest tests

check-mypy:
#	MYPYPATH=$(PYTHONPATH) mypy --namespace-packages --follow-imports=skip tests pyln

$(SDIST_FILE) $(BDIST_FILE):
	uv build

prod-release: check-version $(ARTEFACTS)
	uv publish
