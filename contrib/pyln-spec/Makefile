#! /usr/bin/make

SPECDIR := ../../../lightning-rfc
# This gives us something like 'v1.0-137-gae2d248b7ad8b0965f224c303019ba04c661008f'
GITDESCRIBE := $(shell git -C $(SPECDIR) describe --abbrev=40)
# -> 1.0
BASEVERSION := $(shell echo $(GITDESCRIBE) | sed 's/^v//' | sed 's/-.*//')
# -> 137
POSTVERSION := $(shell echo $(GITDESCRIBE) | sed 's/[^-]*-\([^-]*\)-.*/\1/')
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
	cd $* && flake8 --ignore=E501,E731,W503,E741 --exclude=text.py

# mypy . does not recurse.  I have no idea why...
check-source-mypy-%:
	cd $* && mypy --ignore-missing-imports `find * -name '*.py'`

# Given a bolt number and a variable, get the value from inside the package.
extract = $(shell python3 -c 'from pyln.spec import bolt$1 as bolt;print(bolt.$2)')
# Get the version for this bolt
version = $(call extract,$1,__version__)

# Given a direc the csv version for this bolt.
csv_version = $(call extract,$1,__csv_version__)

# Given a bolt number, get the current version.
sdistfiles = $(foreach b,$(BOLTS),bolt$b/dist/pyln-bolt$b-$(call version,$b).tar.gz)
bdistfiles = $(foreach b,$(BOLTS),bolt$b/dist/pyln_bolt$b-$(call version,$b)-py3-none-any.whl)

%.tar.gz:
	cd $(dir $@)/.. && python3 setup.py sdist

%.whl:
	cd $(dir $@)/.. && python3 setup.py bdist_wheel

ARTEFACTS := $(foreach b,$(BOLTS),$(call bdistfiles,$b) $(call sdistfiles,$b))

test-release-bolt%: $(ARTEFACTS)
	python3 -m twine upload --repository testpypi --skip-existing $(call bdistfiles,$*) $(call sdistfiles,$*)

	# Create a test virtualenv, install from the testpypi and run the
	# tests against it (make sure not to use any virtualenv that may have
	# pyln-proto already installed).
	virtualenv testpypi-$* --python=/usr/bin/python3 --download --always-copy --clear
	# Install the requirements from the prod repo, they are not being kept up to date on the test repo
	testpypi-$*/bin/python3 -m pip install -r requirements.txt pytest flaky pytest-timeout
	testpypi-$*/bin/python3 -m pip install -I --index-url https://test.pypi.org/simple/ --no-deps pyln-bolt$*
	testpypi-$*/bin/python3 -c "from pyln.spec import bolt$* as bolt;assert(bolt.__version__ == '$(call version,$*)')"
	testpypi-$*/bin/pytest bolt$*/tests
	rm -rf testpypi-$*

test-release: check $(foreach b,$(BOLTS),test-release-bolt$b)

prod-release: test-release $(ARTEFACTS)
	python3 -m twine upload $(ARTEFACTS)

refresh: $(CODE_DIRS:%=%/gen_csv_version.py) $(CODE_DIRS:%=%/gen_version.py)

bolt1/pyln/spec/bolt1/csv.py bolt1/pyln/spec/bolt1/text.py: $(SPECDIR)/01-messaging.md Makefile
bolt2/pyln/spec/bolt2/csv.py bolt2/pyln/spec/bolt2/text.py: $(SPECDIR)/02-peer-protocol.md Makefile
bolt4/pyln/spec/bolt4/csv.py bolt4/pyln/spec/bolt4/text.py: $(SPECDIR)/04-onion-routing.md Makefile
bolt7/pyln/spec/bolt7/csv.py bolt7/pyln/spec/bolt7/text.py: $(SPECDIR)/07-routing-gossip.md Makefile

# Getting a bolt number from a target file is nontrivial.
boltnumfromfile = $(subst bolt,,$(word 1,$(subst /, ,$1)))

# Every time this is updated, it increments the version number.
# Only happens when CSV is actually different.
%/gen_csv_version.py: %/csv.py
	@VER=$$(($(call csv_version,$(call boltnumfromfile,$@)) + 1)); echo Upgrading $@ to $$VER; echo '__csv_version__ = "'$$VER'"' > $@

# This is changed every time text is changed.
%/gen_version.py: %/text.py
	echo '__base_version__ = "$(BASEVERSION)"' > $@
	echo '__post_version__ = "$(POSTVERSION)"' >> $@
	echo '__gitversion__ = "$(GITVERSION)"' >> $@

# We update iff it has changed.
$(CODE_DIRS:%=%/csv.py):
	@(echo csv = '['; python3 $(SPECDIR)/tools/extract-formats.py $< | sed 's/\(.*\)/    "\1",/'; echo ']') > $@.tmp
	@if cmp $@ $@.tmp >/dev/null 2>&1; then rm $@.tmp; echo '$@ unchanged'; else mv $@.tmp $@; fi

$(CODE_DIRS:%=%/text.py):
	@echo 'desc = "'`head -n1 $< | cut -c3-`'"' > $@.tmp
	@(echo -n 'text = """'; sed 's,\\,\\\\,g' < $<; echo '"""') >> $@.tmp
	@if cmp $@ $@.tmp >/dev/null 2>&1; then rm $@.tmp; echo '$@ unchanged'; else mv $@.tmp $@; fi
