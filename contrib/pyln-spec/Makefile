#! /usr/bin/make

SPECDIR := ../../../bolts
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
extract = $(shell cat bolt$1/pyln/spec/bolt$1/gen_*version.py | sed -n 's/^$2 = \"\(.*\)\"/\1/p')

# Get the version for this bolt
base_version = $(call extract,$1,__base_version__)
csv_version = $(call extract,$1,__csv_version__)
post_version = $(call extract,$1,__post_version__)

version = $(call base_version,$1).$(call csv_version,$1).$(call post_version,$1)

# Given a bolt number, get the current version.
sdistfiles = $(foreach b,$(BOLTS),bolt$b/dist/pyln-bolt$b-$(call version,$b).tar.gz)
bdistfiles = $(foreach b,$(BOLTS),bolt$b/dist/pyln_bolt$b-$(call version,$b)-py3-none-any.whl)

%.tar.gz:
	cd $(dir $@)/.. && python3 setup.py sdist

%.whl:
	cd $(dir $@)/.. && python3 setup.py bdist_wheel

ARTEFACTS := $(foreach b,$(BOLTS),$(call bdistfiles,$b) $(call sdistfiles,$b))

test-release-%:
	cd bolt$b && poetry publish --repository testpypi

test-release: $(BOLTS:%=prod-release-%)

prod-release-%:
	cd bolt$b && poetry publish

prod-release: $(BOLTS:%=prod-release-%)

# Pattern rules don't work reliably with multiple % in prereqs!
refresh-1: bolt1/pyln/spec/bolt1/gen_csv_version.py bolt1/pyln/spec/bolt1/gen_version.py
	cd bolt1 && poetry version $(call version,1)
refresh-2: bolt2/pyln/spec/bolt2/gen_csv_version.py bolt2/pyln/spec/bolt2/gen_version.py
	cd bolt2 && poetry version $(call version,2)
refresh-4: bolt4/pyln/spec/bolt4/gen_csv_version.py bolt4/pyln/spec/bolt4/gen_version.py
	cd bolt4 && poetry version $(call version,4)
refresh-7: bolt7/pyln/spec/bolt7/gen_csv_version.py bolt7/pyln/spec/bolt7/gen_version.py
	cd bolt7 && poetry version $(call version,7)

refresh: $(BOLTS:%=refresh-%)

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
