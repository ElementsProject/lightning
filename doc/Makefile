#! /usr/bin/make

# Designed to be run one level up
doc-wrongdir:
	$(MAKE) -C .. doc-all

MANPAGES := doc/lightning-cli.1 \
	doc/lightning-delinvoice.7 \
	doc/lightning-getroute.7 \
	doc/lightning-invoice.7 \
	doc/lightning-listinvoice.7 \
	doc/lightning-sendpay.7 \
	doc/lightning-waitinvoice.7 \
	doc/lightning-waitanyinvoice.7

doc-all: $(MANPAGES)

$(MANPAGES): doc/%: doc/%.txt
	@if $(CHANGED_FROM_GIT); then echo a2x --format=manpage $<; a2x --format=manpage $<; else touch $@; fi

doc/protocol-%.svg: test/test_protocol
	test/test_protocol --svg < test/commits/$*.script > $@

protocol-diagrams: $(patsubst %.script, doc/protocol-%.svg, $(notdir $(wildcard test/commits/*.script)))

doc/deployable-lightning.pdf: doc/deployable-lightning.lyx doc/bitcoin.bib
	lyx -E pdf $@ $<

doc/deployable-lightning.tex: doc/deployable-lightning.lyx
	lyx -E latex $@ $<

state-diagrams: doc/normal-states.svg doc/simplified-states.svg doc/error-states.svg doc/full-states.svg

%.svg: %.dot
	dot -Tsvg $< > $@ || (rm -f $@; false)

doc/simplified-states.dot: test/test_state_coverage
	test/test_state_coverage --dot --dot-simplify > $@

doc/normal-states.dot: test/test_state_coverage
	test/test_state_coverage --dot > $@

doc/error-states.dot: test/test_state_coverage
	test/test_state_coverage --dot-all --dot-include-errors > $@

doc/full-states.dot: test/test_state_coverage
	test/test_state_coverage --dot-all --dot-include-errors --dot-include-nops > $@

maintainer-clean: doc-maintainer-clean
clean: doc-clean

doc-maintainer-clean:
	$(RM) doc/deployable-lightning.pdf
	$(RM) $(MANPAGES)

doc-clean:
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

