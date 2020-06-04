#! /usr/bin/make

SPECDIR := ../../../../../../../lightning-rfc

csv.py: $(SPECDIR)/07-routing-gossip.md Makefile
	SPECNUM=`basename $< | sed 's/-.*//'`; (echo csv = '['; python3 $(SPECDIR)/tools/extract-formats.py $< | sed 's/\(.*\)/    "\1",/'; echo ']') > $@
	chmod a+x $@
