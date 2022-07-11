#!/usr/bin/make

.PHONY: bdist sdist release check check-source check-flake8 check-mypy
PKG=testing
VERSION = $(shell python3 -c 'from pyln import ${PKG};print(${PKG}.__version__)')

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = docs
BUILDDIR      = build

SDIST_FILE = "dist/pyln-${PKG}-$(VERSION).tar.gz"
BDIST_FILE = "dist/pyln_${PKG}-$(VERSION)-py3-none-any.whl"
ARTEFACTS = $(BDIST_FILE) $(SDIST_FILE)

check: check-source check-pytest

check-source: check-flake8 check-mypy

check-flake8:
	flake8 --ignore=E501,E731,W503,E741  --exclude '*_pb2*.py,grpc2py.py' pyln tests

check-pytest:
	pytest tests

check-mypy:
#	MYPYPATH=$(PYTHONPATH) mypy --namespace-packages --follow-imports=skip tests pyln

pyproject.toml: pyln/${PKG}/__init__.py
	poetry version ${VERSION}

$(SDIST_FILE) $(BDIST_FILE): pyproject.toml
	poetry build

test-release: check $(ARTEFACTS) pyproject.toml
	# No way of saying "it's ok if files exist" yet
	poetry publish --repository testpypi || /bin/true
	echo Sleeping for PyPI index to update
	sleep 10

	# Generate a requirements.txt file, needed for us to download requirements from the prod pypi instead of the test pypi, since some packages are not published to test pypi.
	poetry export -f requirements.txt --output requirements.txt --without-hashes

	# Create a test virtualenv, install from the testpypi and run the
	# tests against it (make sure not to use any virtualenv that may have
	# pyln-${PKG} already installed).
	virtualenv testpypi --python=/usr/bin/python3 --download --always-copy --clear
	testpypi/bin/python3 -m pip install -r requirements.txt pytest-timeout
	testpypi/bin/python3 -m pip install -I --index-url https://test.pypi.org/simple/ --no-deps pyln-${PKG}==${VERSION}
	testpypi/bin/python3 -c "from pyln import ${PKG};assert(${PKG}.__version__ == '$(VERSION)')"
	testpypi/bin/pytest tests
	rm -rf testpypi

prod-release: test-release $(ARTEFACTS)
	python3 -m twine upload $(ARTEFACTS)

clean:
	rm -rf testpypi
