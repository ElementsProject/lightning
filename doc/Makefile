#! /usr/bin/make

# Designed to be run one level up
doc-wrongdir:
	$(MAKE) -C .. doc-all

MANPAGES := doc/lightning-cli.1 \
	doc/lightningd.8 \
	doc/lightningd-config.5 \
	doc/lightning-autocleaninvoice.7 \
	doc/lightning-check.7 \
	doc/lightning-checkmessage.7 \
	doc/lightning-close.7 \
	doc/lightning-connect.7 \
	doc/lightning-createonion.7 \
	doc/lightning-createinvoice.7 \
	doc/lightning-decodepay.7 \
	doc/lightning-decode.7 \
	doc/lightning-delexpiredinvoice.7 \
	doc/lightning-delinvoice.7 \
	doc/lightning-delpay.7 \
	doc/lightning-dev-sendcustommsg.7 \
	doc/lightning-disconnect.7 \
	doc/lightning-feerates.7 \
	doc/lightning-fetchinvoice.7 \
	doc/lightning-fundchannel.7 \
	doc/lightning-fundchannel_start.7 \
	doc/lightning-fundchannel_complete.7 \
	doc/lightning-fundchannel_cancel.7 \
	doc/lightning-fundpsbt.7 \
	doc/lightning-getroute.7 \
	doc/lightning-getsharedsecret.7 \
	doc/lightning-hsmtool.8 \
	doc/lightning-invoice.7 \
	doc/lightning-keysend.7 \
	doc/lightning-listchannels.7 \
	doc/lightning-listforwards.7 \
	doc/lightning-listfunds.7 \
	doc/lightning-listinvoices.7 \
	doc/lightning-listpays.7 \
	doc/lightning-listpeers.7 \
	doc/lightning-listsendpays.7 \
	doc/lightning-multifundchannel.7 \
	doc/lightning-multiwithdraw.7 \
	doc/lightning-newaddr.7 \
	doc/lightning-notifications.7 \
	doc/lightning-offer.7 \
	doc/lightning-offerout.7 \
	doc/lightning-openchannel_init.7 \
	doc/lightning-openchannel_signed.7 \
	doc/lightning-openchannel_update.7 \
	doc/lightning-pay.7 \
	doc/lightning-plugin.7 \
	doc/lightning-reserveinputs.7 \
	doc/lightning-sendinvoice.7 \
	doc/lightning-sendonion.7 \
	doc/lightning-sendpay.7 \
	doc/lightning-setchannelfee.7 \
	doc/lightning-signmessage.7 \
	doc/lightning-txprepare.7 \
	doc/lightning-txdiscard.7 \
	doc/lightning-txsend.7 \
	doc/lightning-unreserveinputs.7 \
	doc/lightning-utxopsbt.7 \
	doc/lightning-waitinvoice.7 \
	doc/lightning-waitanyinvoice.7 \
	doc/lightning-waitblockheight.7 \
	doc/lightning-waitsendpay.7 \
	doc/lightning-withdraw.7 \
	doc/lightning-ping.7 \
	doc/lightning-stop.7 \
	doc/lightning-signpsbt.7 \
	doc/lightning-sendpsbt.7 \
	doc/lightning-getinfo.7 \
	doc/lightning-listtransactions.7 \
	doc/lightning-listnodes.7 \
	doc/lightning-listconfigs.7 \
	doc/lightning-help.7 \
	doc/lightning-getlog.7

doc-all: $(MANPAGES) doc/index.rst

$(MANPAGES): doc/%: doc/%.md
	@if $(call SHA256STAMP_CHANGED); then $(call VERBOSE, "mrkd $<", mrkd $< $@ && $(call SHA256STAMP,\")); else touch $@; fi

$(MANPAGES): FORCE

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
check: check-manpages

# This needs plugins, too.
check-manpages: all-programs
	@tools/check-manpage.sh cli/lightning-cli doc/lightning-cli.1.md
	@tools/check-manpage.sh "lightningd/lightningd --lightning-dir=/tmp/" doc/lightningd-config.5.md

doc-maintainer-clean:
	$(RM) $(MANPAGES)

doc-clean:
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

doc/index.rst: $(MANPAGES:=.md)
	@$(call VERBOSE, "genidx $@",(grep -v "^   lightning.*\.[0-9]\.md>$$" $@; for m in $$(cd doc && ls lightningd*.[0-9].md lightning-*.[0-9].md); do echo "   $${m%.[0-9].md} <$$m>"; done |$(SORT)) > $@.tmp.$$$$ && mv $@.tmp.$$$$ $@)
