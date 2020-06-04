#! /usr/bin/make

SPECDIR := ../../../../../../../lightning-rfc

# Only consider specs which have types in them.
SPECS := $(shell fgrep -l '1. type' $(SPECDIR)/[0-9]*.md)

bolts.py: $(SPECS) Makefile
	for f in $(SPECS); do SPECNUM=`basename $$f | sed 's/-.*//'`; echo bolt_$${SPECNUM}_csv = '['; python3 $(SPECDIR)/tools/extract-formats.py $$f | sed 's/\(.*\)/    "\1",/'; echo ']'; done > $@
	chmod a+x $@

CSVFILES = $(SPECS:%.md=bolt%.py)

refresh: $(CSVFILES)
