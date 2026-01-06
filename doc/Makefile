#! /usr/bin/make

# Designed to be run one level up
doc-wrongdir:
	$(MAKE) -C .. doc-all

MARKDOWNPAGES := doc/addgossip.7 \
	doc/addpsbtoutput.7 \
	doc/askrene-age.7 \
	doc/askrene-bias-channel.7 \
	doc/askrene-bias-node.7 \
	doc/askrene-create-channel.7 \
	doc/askrene-create-layer.7 \
	doc/askrene-disable-node.7 \
	doc/askrene-inform-channel.7 \
	doc/askrene-listlayers.7 \
	doc/askrene-listreservations.7 \
	doc/askrene-remove-layer.7 \
	doc/askrene-reserve.7 \
	doc/askrene-unreserve.7 \
	doc/askrene-update-channel.7 \
	doc/autoclean-once.7 \
	doc/autoclean-status.7 \
	doc/batching.7 \
	doc/bkpr-channelsapy.7 \
	doc/bkpr-dumpincomecsv.7 \
	doc/bkpr-editdescriptionbyoutpoint.7 \
	doc/bkpr-editdescriptionbypaymentid.7 \
	doc/bkpr-inspect.7 \
	doc/bkpr-listaccountevents.7 \
	doc/bkpr-listbalances.7 \
	doc/bkpr-listincome.7 \
	doc/blacklistrune.7 \
	doc/cancelrecurringinvoice.7 \
	doc/check.7 \
	doc/checkmessage.7 \
	doc/checkrune.7 \
	doc/close.7 \
	doc/commando.7 \
	doc/connect.7 \
	doc/createinvoice.7 \
	doc/createonion.7 \
	doc/createrune.7 \
	doc/datastore.7 \
	doc/datastoreusage.7 \
	doc/decode.7 \
	doc/decodepay.7 \
	doc/deldatastore.7 \
	doc/delforward.7 \
	doc/delinvoice.7 \
	doc/delnetworkevent.7 \
	doc/delpay.7 \
	doc/deprecations.7 \
	doc/dev-forget-channel.7 \
	doc/dev-splice.7 \
	doc/disableinvoicerequest.7 \
	doc/disableoffer.7 \
	doc/disconnect.7 \
	doc/emergencyrecover.7 \
	doc/enableoffer.7 \
	doc/exposesecret.7 \
	doc/feerates.7 \
	doc/fetchbip353.7 \
	doc/fetchinvoice.7 \
	doc/fundchannel_cancel.7 \
	doc/fundchannel_complete.7 \
	doc/fundchannel.7 \
	doc/fundchannel_start.7 \
	doc/funderupdate.7 \
	doc/fundpsbt.7 \
	doc/getemergencyrecoverdata.7 \
	doc/getinfo.7 \
	doc/getlog.7 \
	doc/getroute.7 \
	doc/getroutes.7 \
	doc/help.7 \
	doc/injectonionmessage.7 \
	doc/injectpaymentonion.7 \
	doc/invoice.7 \
	doc/invoicerequest.7 \
	doc/keysend.7 \
	doc/listaddresses.7 \
	doc/listchainmoves.7 \
	doc/listchannelmoves.7 \
	doc/listchannels.7 \
	doc/listclosedchannels.7 \
	doc/listconfigs.7 \
	doc/listdatastore.7 \
	doc/listforwards.7 \
	doc/listfunds.7 \
	doc/listhtlcs.7 \
	doc/listinvoicerequests.7 \
	doc/listinvoices.7 \
	doc/listnetworkevents.7 \
	doc/listnodes.7 \
	doc/listoffers.7 \
	doc/listpays.7 \
	doc/listpeerchannels.7 \
	doc/listpeers.7 \
	doc/listsendpays.7 \
	doc/listtransactions.7 \
	doc/makesecret.7 \
	doc/multifundchannel.7 \
	doc/multiwithdraw.7 \
	doc/newaddr.7 \
	doc/notifications.7 \
	doc/offer.7 \
	doc/openchannel_abort.7 \
	doc/openchannel_bump.7 \
	doc/openchannel_init.7 \
	doc/openchannel_signed.7 \
	doc/openchannel_update.7 \
	doc/parsefeerate.7 \
	doc/pay.7 \
	doc/ping.7 \
	doc/plugin.7 \
	doc/preapproveinvoice.7 \
	doc/preapprovekeysend.7 \
	doc/reckless.7 \
	doc/recoverchannel.7 \
	doc/recover.7 \
	doc/renepay.7 \
	doc/renepaystatus.7 \
	doc/reserveinputs.7 \
	doc/sendcustommsg.7 \
	doc/sendinvoice.7 \
	doc/sendonion.7 \
	doc/sendpay.7 \
	doc/sendpsbt.7 \
	doc/setchannel.7 \
	doc/setconfig.7 \
	doc/setpsbtversion.7 \
	doc/showrunes.7 \
	doc/signinvoice.7 \
	doc/signmessage.7 \
	doc/signmessagewithkey.7 \
	doc/signpsbt.7 \
	doc/splice_init.7 \
	doc/splice_signed.7 \
	doc/splice_update.7 \
	doc/staticbackup.7 \
	doc/stop.7 \
	doc/txdiscard.7 \
	doc/txprepare.7 \
	doc/txsend.7 \
	doc/unreserveinputs.7 \
	doc/upgradewallet.7 \
	doc/utxopsbt.7 \
	doc/waitanyinvoice.7 \
	doc/waitblockheight.7 \
	doc/waitinvoice.7 \
	doc/wait.7 \
	doc/waitsendpay.7 \
	doc/withdraw.7 \
	doc/xpay.7

ifeq ($(HAVE_SQLITE3),1)
MARKDOWNPAGES += doc/listsqlschemas.7 doc/sql.7
endif

PREFIXED_MANPAGES := $(MARKDOWNPAGES:doc/%.7=doc/lightning-%.7)
NON_PREFIXED_MANPAGES := doc/lightning-cli.1 \
	doc/lightningd.8 \
	doc/lightningd-config.5 \
	doc/lightningd-rpc.7 \
	doc/lightning-hsmtool.8 \
	doc/lightning-downgrade.8 \
	doc/lightning-reckless.1

MANPAGES := $(PREFIXED_MANPAGES) $(NON_PREFIXED_MANPAGES)

MARKDOWNPAGES_WITH_EXT := $(MARKDOWNPAGES:=.md)
NON_PREFIXED_MARKDOWNPAGES_WITH_EXT := $(NON_PREFIXED_MANPAGES:=.md)
OLD_MARKDOWNPAGES_WITH_EXT := $(PREFIXED_MANPAGES:=.md)


# - Read the json template from schemas/sql-template.json
# - Generate the tables schema via plugins/sql
# - Merge both and generate final schemas/sql.json
doc/schemas/sql.json: doc/schemas/sql-template.json plugins/sql
	@plugins/sql --print-docs | jq --arg sqldata "$$(awk '{printf "%s\n", $$0}')" '.tables += [$$sqldata]' $< > "$@.tmp" && mv "$@.tmp" "$@";

doc-all: $(MANPAGES) doc/index.rst

SCHEMAS := $(wildcard doc/schemas/*.json) $(wildcard doc/schemas/notification/*.json)

# Don't try to build sql.json tables with plugins/sql if we don't have sqlite3
ifeq ($(HAVE_SQLITE3),0)
SCHEMAS := $(filter-out doc/schemas/sql.json, $(SCHEMAS))
endif

check-fmt-schemas: $(SCHEMAS:%=check-fmt-schema/%)
fmt-schemas: $(SCHEMAS:%=fmt-schema/%)

check-fmt-schema/%: %
	@jq . < "$*" > "$*".fmt && diff -u "$*" "$*.fmt" && rm "$*.fmt"

fmt-schema/%: %
	@jq . < "$*" > "$*".fmt && cat "$*".fmt > "$*" && rm "$*.fmt"

check-doc: check-config-docs check-manpages check-fmt-schemas

# These are hard to use in $(call) functions.
LBRACKET=(
RBRACKET=)

$(MARKDOWNPAGES_WITH_EXT): doc/%.7.md: doc/schemas/%.json tools/fromschema.py
	@tools/fromschema.py --markdownfile=$@ $< > $@.tmp && mv $@.tmp $@

LOWDOWN := lowdown

# For versions in documentation, we don't change with every git version, to
# save build time.  We build them on new tags or keep them on pre-next-release version.
doc/.doc_version: version_gen.h
	@case "$(VERSION)" in \
	*-*-g*) \
		DOC_VERSION="pre-$(CLN_NEXT_VERSION)";; \
	*) \
		DOC_VERSION="$(VERSION)";; \
	esac; \
	echo $$DOC_VERSION > $@.new
	@if cmp $@.new $@ >/dev/null 2>&1; then rm -f $@.new; else mv $@.new $@; $(ECHO) Documentation version updated to `cat doc/.doc_version`; fi

$(PREFIXED_MANPAGES): doc/lightning-%: doc/%.md tools/md2man.sh doc/.doc_version
	@VERSION=`cat doc/.doc_version` SED=$(SED) tools/md2man.sh $(LOWDOWN) $<
$(NON_PREFIXED_MANPAGES): doc/%: doc/%.md tools/md2man.sh doc/.doc_version
	@VERSION=`cat doc/.doc_version` SED=$(SED) tools/md2man.sh $(LOWDOWN) $<

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

clean: doc-clean
check: check-manpages

# This needs plugins, too.
check-manpages: all-programs check-config-docs default-targets
	@SED=$(SED) tools/check-manpage.sh cli/lightning-cli doc/lightning-cli.1.md
	@SED=$(SED) tools/check-manpage.sh "lightningd/lightningd --lightning-dir=/tmp/" doc/lightningd-config.5.md
	@awk '/^$$/ { do { getline } while ($$0 ~ /^( {4,}|\t)/) } /^\s*```/ { do { getline } while ($$0 !~ /^\s*```/) } /^([^`_\\]|`([^`\\]|\\.)*`|\b_|_\b|\\.)*\B_\B/ { print "" ; print "Unescaped underscore at " FILENAME ":" NR ":" ; print ; ret = 1 } ENDFILE { NR = 0 } END { exit ret }' doc/*.[0-9].md

# Makes sure that fields mentioned in schema are in man page, and vice versa.
check-config-docs:
	@for c in `sed -n 's/^	"\(.*\)": {/\1/p' doc/schemas/listconfigs.json | grep -v '^# version$$' | grep -v '^plugins$$' | grep -v '^important-plugins$$'`; do if ! grep -q "^ \*\*$$c\*\*" doc/lightningd-config.5.md; then echo "$$c undocumented!"; exit 1; fi; done
	@for c in `grep -v '\[plugin ' doc/lightningd-config.5.md | sed -n 's/^ \*\*\([^*]*\)\*\*.*/\1/p' | grep -v '^\(help\|version\|mainnet\|testnet\|testnet4\|signet\|plugin\|important-plugin\|plugin-dir\|clear-plugins\)$$'`; do if ! grep -q '"'"$$c"'"' doc/schemas/listconfigs.json; then echo "$$c documented but not in schema!"; exit 1; fi; done

doc-clean:
	$(RM) $(MANPAGES) $(MARKDOWNPAGES_WITH_EXT) $(OLD_MARKDOWNPAGES_WITH_EXT) doc/.doc_version
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

doc/index.rst: $(MARKDOWNPAGES_WITH_EXT) $(NON_PREFIXED_MARKDOWNPAGES_WITH_EXT) Makefile
	@$(call VERBOSE, "genidx $@", \
	  for m in $(MARKDOWNPAGES_WITH_EXT) $(NON_PREFIXED_MARKDOWNPAGES_WITH_EXT); do \
	    base=$$(basename "$$m"); \
	    echo "$$base" | \
	      $(SED) -E 's/^(.*)\.([0-9]+)\.md$$/\1 <\1.\2.md>/; t; s/^(.*)\.md$$/\1 <\1.md>/'; \
	  done | \
	  LC_ALL=C sort | \
	  $(PYTHON) devtools/blockreplace.py doc/index.rst manpages --language=rst --indent "   " \
	)

# Overridden by GH CI if necessary.
BASE_REF=master

check-source:
