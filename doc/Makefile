#! /usr/bin/make

# Designed to be run one level up
doc-wrongdir:
	$(MAKE) -C .. doc-all

GENERATE_MARKDOWN := doc/lightning-addgossip.7 \
	doc/lightning-addpsbtoutput.7 \
	doc/lightning-autoclean-once.7 \
	doc/lightning-autoclean-status.7 \
	doc/lightning-batching.7 \
	doc/lightning-bkpr-channelsapy.7 \
	doc/lightning-bkpr-dumpincomecsv.7 \
	doc/lightning-bkpr-inspect.7 \
	doc/lightning-bkpr-listaccountevents.7 \
	doc/lightning-bkpr-listbalances.7 \
	doc/lightning-bkpr-listincome.7 \
	doc/lightning-blacklistrune.7 \
	doc/lightning-check.7 \
	doc/lightning-checkmessage.7 \
	doc/lightning-checkrune.7 \
	doc/lightning-close.7 \
	doc/lightning-commando-blacklist.7 \
	doc/lightning-commando.7 \
	doc/lightning-commando-listrunes.7 \
	doc/lightning-commando-rune.7 \
	doc/lightning-connect.7 \
	doc/lightning-createinvoice.7 \
	doc/lightning-createonion.7 \
	doc/lightning-createrune.7 \
	doc/lightning-datastore.7 \
	doc/lightning-datastoreusage.7 \
	doc/lightning-decode.7 \
	doc/lightning-decodepay.7 \
	doc/lightning-deldatastore.7 \
 	doc/lightning-delexpiredinvoice.7 \
	doc/lightning-delforward.7 \
	doc/lightning-delinvoice.7 \
	doc/lightning-delpay.7 \
	doc/lightning-deprecations.7 \
	doc/lightning-disableinvoicerequest.7 \
	doc/lightning-disableoffer.7 \
	doc/lightning-disconnect.7 \
	doc/lightning-emergencyrecover.7 \
	doc/lightning-feerates.7 \
	doc/lightning-fetchinvoice.7 \
	doc/lightning-fundchannel_cancel.7 \
	doc/lightning-fundchannel_complete.7 \
	doc/lightning-fundchannel.7 \
	doc/lightning-fundchannel_start.7 \
	doc/lightning-funderupdate.7 \
	doc/lightning-fundpsbt.7 \
	doc/lightning-getinfo.7 \
	doc/lightning-getlog.7 \
	doc/lightning-getroute.7 \
	doc/lightning-help.7 \
	doc/lightning-invoice.7 \
	doc/lightning-invoicerequest.7 \
	doc/lightning-keysend.7 \
	doc/lightning-listchannels.7 \
	doc/lightning-listclosedchannels.7 \
	doc/lightning-listconfigs.7 \
	doc/lightning-listdatastore.7 \
	doc/lightning-listforwards.7 \
	doc/lightning-listfunds.7 \
	doc/lightning-listhtlcs.7 \
	doc/lightning-listinvoicerequests.7 \
	doc/lightning-listinvoices.7 \
	doc/lightning-listnodes.7 \
	doc/lightning-listoffers.7 \
	doc/lightning-listpays.7 \
	doc/lightning-listpeerchannels.7 \
	doc/lightning-listpeers.7 \
	doc/lightning-listsendpays.7 \
	doc/lightning-listtransactions.7 \
	doc/lightning-makesecret.7 \
	doc/lightning-multifundchannel.7 \
	doc/lightning-multiwithdraw.7 \
	doc/lightning-newaddr.7 \
	doc/lightning-notifications.7 \
	doc/lightning-offer.7 \
	doc/lightning-openchannel_abort.7 \
	doc/lightning-openchannel_bump.7 \
	doc/lightning-openchannel_init.7 \
	doc/lightning-openchannel_signed.7 \
	doc/lightning-openchannel_update.7 \
	doc/lightning-parsefeerate.7 \
	doc/lightning-pay.7 \
	doc/lightning-ping.7 \
	doc/lightning-plugin.7 \
	doc/lightning-preapproveinvoice.7 \
	doc/lightning-preapprovekeysend.7 \
	doc/lightning-recoverchannel.7 \
	doc/lightning-recover.7 \
	doc/lightning-renepay.7 \
	doc/lightning-renepaystatus.7 \
	doc/lightning-reserveinputs.7 \
	doc/lightning-sendcustommsg.7 \
	doc/lightning-sendinvoice.7 \
	doc/lightning-sendonion.7 \
	doc/lightning-sendonionmessage.7 \
	doc/lightning-sendpay.7 \
	doc/lightning-sendpsbt.7 \
	doc/lightning-setchannel.7 \
	doc/lightning-setconfig.7 \
	doc/lightning-setpsbtversion.7 \
	doc/lightning-showrunes.7 \
	doc/lightning-signinvoice.7 \
	doc/lightning-signmessage.7 \
	doc/lightning-signpsbt.7 \
	doc/lightning-splice_init.7 \
	doc/lightning-splice_signed.7 \
	doc/lightning-splice_update.7 \
 	doc/lightning-staticbackup.7 \
	doc/lightning-stop.7 \
	doc/lightning-txdiscard.7 \
	doc/lightning-txprepare.7 \
	doc/lightning-txsend.7 \
	doc/lightning-unreserveinputs.7 \
	doc/lightning-upgradewallet.7 \
	doc/lightning-utxopsbt.7 \
	doc/lightning-waitanyinvoice.7 \
	doc/lightning-waitblockheight.7 \
	doc/lightning-waitinvoice.7 \
	doc/lightning-wait.7 \
	doc/lightning-waitsendpay.7 \
	doc/lightning-withdraw.7

ifeq ($(HAVE_SQLITE3),1)
GENERATE_MARKDOWN += doc/lightning-listsqlschemas.7 \
	doc/lightning-sql.7
endif

MANPAGES := $(GENERATE_MARKDOWN) \
	doc/lightning-cli.1 \
	doc/lightningd.8 \
	doc/lightningd-config.5 \
	doc/lightningd-rpc.7 \
	doc/lightning-hsmtool.8 \
	doc/reckless.7

MARKDOWN_WITH_SCHEMA := $(GENERATE_MARKDOWN:=.md)

# - Read the json template from schemas/lightning-sql-template.json
# - Generate the tables schema via plugins/sql
# - Merge both and generate final schemas/lightning-sql.json
doc/schemas/lightning-sql.json: doc/schemas/lightning-sql-template.json plugins/sql
	@plugins/sql --print-docs | jq --arg sqldata "$$(awk '{printf "%s\n", $$0}')" '.tables += [$$sqldata]' $< > "$@.tmp" && mv "$@.tmp" "$@";

doc-all: $(MANPAGES) doc/index.rst

SCHEMAS := $(wildcard doc/schemas/lightning-*.json)

# Don't try to build lightning-sql.json tables with plugins/sql if we don't have sqlite3
ifeq ($(HAVE_SQLITE3),0)
SCHEMAS := $(filter-out doc/schemas/lightning-sql.json, $(SCHEMAS))
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

$(MARKDOWN_WITH_SCHEMA): doc/lightning-%.7.md: doc/schemas/lightning-%.json tools/fromschema.py
	@tools/fromschema.py --markdownfile=$@ $< > $@.tmp && mv $@.tmp $@

# If we need to build lowdown, make tools/md2man.sh depend on it.
# That way it's not used in SHA256STAMP (which only uses direct
# dependencies), but make will be forced to build it.
ifeq ($(HAVE_LOWDOWN),0)
LOWDOWN := $(TARGET_DIR)/lowdown-build/bin/lowdown
tools/md2man.sh: $(LOWDOWN)
	touch $@
else
LOWDOWN := lowdown
endif

$(MANPAGES): doc/%: doc/%.md tools/md2man.sh version_gen.h
	@VERSION=$(VERSION) tools/md2man.sh $(LOWDOWN) $< > $@

$(MANPAGES): $(FORCE)
$(MARKDOWN_WITH_SCHEMA): $(FORCE)

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
check-manpages: all-programs check-config-docs default-targets
	@tools/check-manpage.sh cli/lightning-cli doc/lightning-cli.1.md
	@tools/check-manpage.sh "lightningd/lightningd --lightning-dir=/tmp/" doc/lightningd-config.5.md
	@awk '/^$$/ { do { getline } while ($$0 ~ /^( {4,}|\t)/) } /^\s*```/ { do { getline } while ($$0 !~ /^\s*```/) } /^([^`_\\]|`([^`\\]|\\.)*`|\b_|_\b|\\.)*\B_\B/ { print "" ; print "Unescaped underscore at " FILENAME ":" NR ":" ; print ; ret = 1 } ENDFILE { NR = 0 } END { exit ret }' doc/*.[0-9].md

# Makes sure that fields mentioned in schema are in man page, and vice versa.
check-config-docs:
	@for c in `sed -n 's/^	"\(.*\)": {/\1/p' doc/schemas/lightning-listconfigs.json | grep -v '^# version$$' | grep -v '^plugins$$' | grep -v '^important-plugins$$'`; do if ! grep -q "^ \*\*$$c\*\*" doc/lightningd-config.5.md; then echo "$$c undocumented!"; exit 1; fi; done
	@for c in `grep -v '\[plugin ' doc/lightningd-config.5.md | sed -n 's/^ \*\*\([^*]*\)\*\*.*/\1/p' | grep -v '^\(help\|version\|mainnet\|testnet\|signet\|plugin\|important-plugin\|plugin-dir\|clear-plugins\)$$'`; do if ! grep -q '"'"$$c"'"' doc/schemas/lightning-listconfigs.json; then echo "$$c documented but not in schema!"; exit 1; fi; done

doc-maintainer-clean:
	$(RM) $(MANPAGES)

doc-clean:
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

doc/index.rst: $(MANPAGES:=.md)
	@$(call VERBOSE, "genidx $@", \
	  find doc -maxdepth 1 -name '*\.[0-9]\.md' | \
	  cut -b 5- | LC_ALL=C sort | \
	  sed "s/\(.*\)\.\(.*\).*\.md/\1 <\1.\2.md>/" | \
	  $(PYTHON) devtools/blockreplace.py doc/index.rst manpages --language=rst --indent "   " \
	)

# Overridden by GH CI if necessary.
BASE_REF=master

check-source:
