#!/usr/bin/make

.PHONY: bdist sdist release check check-source check-flake8 check-mypy
PKG=proto
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
	flake8 --ignore=E501,E731,W503,E741

check-pytest:
	pytest tests

check-mypy:
	#mypy --namespace-packages tests pyln
	echo mypy disabled for pyln-proto

$(SDIST_FILE):
	python3 setup.py sdist

$(BDIST_FILE):
	python3 setup.py bdist_wheel

test-release: check $(ARTEFACTS)
	python3 -m twine upload --repository testpypi --skip-existing $(ARTEFACTS)

	# Create a test virtualenv, install from the testpypi and run the
	# tests against it (make sure not to use any virtualenv that may have
	# pyln-${PKG} already installed).
	virtualenv testpypi --python=/usr/bin/python3 --download --always-copy --clear
	# Install the requirements from the prod repo, they are not being kept up to date on the test repo
	testpypi/bin/python3 -m pip install -r requirements.txt flaky pytest-timeout
	testpypi/bin/python3 -m pip install -I --index-url https://test.pypi.org/simple/ --no-deps pyln-${PKG}
	testpypi/bin/python3 -c "from pyln import ${PKG};assert(${PKG}.__version__ == '$(VERSION)')"
	testpypi/bin/pytest tests
	rm -rf testpypi

prod-release: test-release $(ARTEFACTS)
	python3 -m twine upload $(ARTEFACTS)

clean:
	rm -rf testpypi
