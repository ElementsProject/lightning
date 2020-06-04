#! /usr/bin/make

check:
	pytest

check-source: check-flake8 check-mypy

check-flake8:
	flake8 --ignore=E501,E731,W503

# mypy . does not recurse.  I have no idea why...
check-mypy:
	mypy --ignore-missing-imports `find * -name '*.py'`
