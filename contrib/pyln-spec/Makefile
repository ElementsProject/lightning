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
