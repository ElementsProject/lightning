#! /usr/bin/make

SPECDIR := ../../../lightning-rfc
# This gives us something like 'v1.0-137-gae2d248b7ad8b0965f224c303019ba04c661008f'
GITDESCRIBE := $(shell git -C $(SPECDIR) describe --abbrev=40)
# PEP 440 requires numbers only, but allows -post (setuptools prefers .post though):
VERSION := $(shell echo $(GITDESCRIBE) | sed 's/^v//' | sed 's/-/.post/' | sed 's/-g.*//')
# This maintains -dirty, if present.
GITVERSION := $(shell echo $(GITDESCRIBE) | sed 's/.*-g//')

BOLTS := 1 2 4 7

DIRS := $(foreach b,$(BOLTS),bolt$b)
CODE_DIRS := $(foreach b,$(BOLTS),bolt$b/pyln/spec/bolt$b)

check: $(DIRS:%=check-pytest-%)
check-pytest-%:
	cd $* && pytest 

check-source: check-source-flake8 check-source-mypy
check-source-flake8: $(DIRS:%=check-source-flake8-%)
check-source-mypy: $(DIRS:%=check-source-mypy-%)

check-source-flake8-%:
	cd $* && flake8 --ignore=E501,E731,W503 --exclude=gen.py

# mypy . does not recurse.  I have no idea why...
check-source-mypy-%:
	cd $* && mypy --ignore-missing-imports `find * -name '*.py'`

# There's a smarter way to do this, probably.

VERSION_BOLT1 := $(shell python3 -c 'from pyln.spec import bolt1 as bolt;print(bolt.__version__)')
VERSION_BOLT2 := $(shell python3 -c 'from pyln.spec import bolt2 as bolt;print(bolt.__version__)')
VERSION_BOLT4 := $(shell python3 -c 'from pyln.spec import bolt4 as bolt;print(bolt.__version__)')
VERSION_BOLT7 := $(shell python3 -c 'from pyln.spec import bolt7 as bolt;print(bolt.__version__)')

SDIST_FILE1 := bolt1/dist/pyln-bolt1-$(VERSION_BOLT1).tar.gz
BDIST_FILE1 := bolt1/dist/pyln_bolt1-$(VERSION_BOLT1)-py3-none-any.whl

SDIST_FILE2 := bolt2/dist/pyln-bolt2-$(VERSION_BOLT2).tar.gz
BDIST_FILE2 := bolt2/dist/pyln_bolt2-$(VERSION_BOLT2)-py3-none-any.whl

SDIST_FILE4 := bolt4/dist/pyln-bolt4-$(VERSION_BOLT4).tar.gz
BDIST_FILE4 := bolt4/dist/pyln_bolt4-$(VERSION_BOLT4)-py3-none-any.whl

SDIST_FILE7 := bolt7/dist/pyln-bolt7-$(VERSION_BOLT7).tar.gz
BDIST_FILE7 := bolt7/dist/pyln_bolt7-$(VERSION_BOLT7)-py3-none-any.whl

%.tar.gz:
	cd $(dir $@)/.. && python3 setup.py sdist

%.whl:
	cd $(dir $@)/.. && python3 setup.py bdist_wheel

ARTEFACTS = $(foreach b,$(BOLTS),$(BDIST_FILE$(b)) $(SDIST_FILE$(b)))

test-release-bolt%: $(ARTEFACTS)
	python3 -m twine upload --repository testpypi --skip-existing $(BDIST_FILE$*)

	# Create a test virtualenv, install from the testpypi and run the
	# tests against it (make sure not to use any virtualenv that may have
	# pyln-proto already installed).
	virtualenv testpypi-$* --python=/usr/bin/python3 --download --always-copy --clear
	# Install the requirements from the prod repo, they are not being kept up to date on the test repo
	testpypi-$*/bin/python3 -m pip install -r requirements.txt pytest flaky pytest-timeout
	testpypi-$*/bin/python3 -m pip install -I --index-url https://test.pypi.org/simple/ --no-deps pyln-bolt$*
	testpypi-$*/bin/python3 -c "from pyln.spec import bolt$* as bolt;assert(bolt.__version__ == '$(VERSION_BOLT$*)')"
	testpypi-$*/bin/pytest bolt$*/tests
	rm -rf testpypi-$*

test-release: check $(foreach b,$(BOLTS),test-release-bolt$b)

prod-release: test $(ARTEFACTS)
	python3 -m twine upload $(ARTEFACTS)

refresh: $(CODE_DIRS:%=%/gen_version.py)

bolt1/pyln/spec/bolt1/gen.py: $(SPECDIR)/01-messaging.md Makefile
bolt2/pyln/spec/bolt2/gen.py: $(SPECDIR)/02-peer-protocol.md Makefile
bolt4/pyln/spec/bolt4/gen.py: $(SPECDIR)/04-onion-routing.md Makefile
bolt7/pyln/spec/bolt7/gen.py: $(SPECDIR)/07-routing-gossip.md Makefile

%/gen_version.py: %/gen.py
	echo '__version__ = "$(VERSION)"' > $@
	echo '__gitversion__ = "$(GITVERSION)"' >> $@

# We update iff it has changed.
$(CODE_DIRS:%=%/gen.py):
	@(echo csv = '['; python3 $(SPECDIR)/tools/extract-formats.py $< | sed 's/\(.*\)/    "\1",/'; echo ']') > $@.tmp
	@echo 'desc = "'`head -n1 $< | cut -c3-`'"' >> $@.tmp
	@(echo -n 'text = """'; sed 's,\\,\\\\,g' < $<; echo '"""') >> $@.tmp
	@if cmp $@ $@.tmp >/dev/null 2>&1; then rm $@.tmp; else mv $@.tmp $@; fi
