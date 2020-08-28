#! /usr/bin/make

.PHONY: bdist sdist release check check-source check-flake8 check-mypy
VERSION = $(shell python3 -c 'from pyln import testing;print(testing.__version__)')

SDIST_FILE = "dist/pyln-testing-$(VERSION).tar.gz"
BDIST_FILE = "dist/pyln_testing-$(VERSION)-py3-none-any.whl"
ARTEFACTS = $(BDIST_FILE) $(SDIST_FILE)

check:
#	pytest

check-source: check-flake8 check-mypy

check-flake8:
	flake8 --ignore=E501,E731,W503

# mypy . does not recurse.  I have no idea why...
check-mypy:
	mypy --ignore-missing-imports `find pyln/testing -name '*.py'`

$(SDIST_FILE):
	python3 setup.py sdist

$(BDIST_FILE):
	python3 setup.py bdist_wheel

test-release: check $(ARTEFACTS)
	python3 -m twine upload --repository testpypi --skip-existing $(ARTEFACTS)

	# Create a test virtualenv, install from the testpypi and run the
	# tests against it (make sure not to use any virtualenv that may have
	# pyln-testing already installed).
	virtualenv testpypi --python=/usr/bin/python3 --download --always-copy --clear
	# Install the requirements from the prod repo, they are not being kept up to date on the test repo
	testpypi/bin/python3 -m pip install -r requirements.txt flaky pytest-timeout
	testpypi/bin/python3 -m pip install -I --index-url https://test.pypi.org/simple/ --no-deps pyln-testing
	testpypi/bin/python3 -c "from pyln import testing;assert(testing.__version__ == '$(VERSION)')"
	testpypi/bin/pytest tests
	rm -rf testpypi

prod-release: test-release $(ARTEFACTS)
	python3 -m twine upload $(ARTEFACTS)

clean:
	rm -rf testpypi
