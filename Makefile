#! /usr/bin/make
NAME=Bitcoin Savings & Trust Daily Interest

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../lightning-rfc/
BOLTVERSION := master

# If you don't have (working) valgrind.
#NO_VALGRIND := 1

# This is where we add new features as bitcoin adds them.
FEATURES :=

TEST_PROGRAMS :=				\
	test/test_protocol			\
	test/test_sphinx

BITCOIN_SRC :=					\
	bitcoin/base58.c			\
	bitcoin/block.c			\
	bitcoin/locktime.c			\
	bitcoin/pubkey.c			\
	bitcoin/pullpush.c			\
	bitcoin/script.c			\
	bitcoin/shadouble.c			\
	bitcoin/signature.c			\
	bitcoin/tx.c				\
	bitcoin/varint.c

BITCOIN_OBJS := $(BITCOIN_SRC:.c=.o)

CORE_SRC :=					\
	close_tx.c				\
	find_p2sh_out.c				\
	lightning.pb-c.c			\
	opt_bits.c				\
	permute_tx.c				\
	protobuf_convert.c			\
	utils.c					\
	version.c
CORE_OBJS := $(CORE_SRC:.c=.o)

CCAN_OBJS :=					\
	ccan-crypto-ripemd160.o			\
	ccan-crypto-sha256.o			\
	ccan-crypto-shachain.o			\
	ccan-asort.o				\
	ccan-crypto-siphash24.o			\
	ccan-err.o				\
	ccan-htable.o				\
	ccan-ilog.o				\
	ccan-io-io.o				\
	ccan-io-poll.o				\
	ccan-isaac.o				\
	ccan-isaac64.o				\
	ccan-list.o				\
	ccan-mem.o				\
	ccan-noerr.o				\
	ccan-opt-helpers.o			\
	ccan-opt-parse.o			\
	ccan-opt-usage.o			\
	ccan-opt.o				\
	ccan-pipecmd.o				\
	ccan-read_write_all.o			\
	ccan-str-hex.o				\
	ccan-str.o				\
	ccan-take.o				\
	ccan-tal-grab_file.o			\
	ccan-tal-path.o				\
	ccan-tal-str.o				\
	ccan-tal.o				\
	ccan-time.o				\
	ccan-timer.o

CCAN_HEADERS :=						\
	$(CCANDIR)/config.h				\
	$(CCANDIR)/ccan/alignof/alignof.h		\
	$(CCANDIR)/ccan/array_size/array_size.h		\
	$(CCANDIR)/ccan/asort/asort.h			\
	$(CCANDIR)/ccan/build_assert/build_assert.h	\
	$(CCANDIR)/ccan/cast/cast.h			\
	$(CCANDIR)/ccan/cdump/cdump.h			\
	$(CCANDIR)/ccan/check_type/check_type.h		\
	$(CCANDIR)/ccan/compiler/compiler.h		\
	$(CCANDIR)/ccan/container_of/container_of.h	\
	$(CCANDIR)/ccan/cppmagic/cppmagic.h		\
	$(CCANDIR)/ccan/crypto/ripemd160/ripemd160.h	\
	$(CCANDIR)/ccan/crypto/sha256/sha256.h		\
	$(CCANDIR)/ccan/crypto/shachain/shachain.h	\
	$(CCANDIR)/ccan/crypto/siphash24/siphash24.h	\
	$(CCANDIR)/ccan/endian/endian.h			\
	$(CCANDIR)/ccan/err/err.h			\
	$(CCANDIR)/ccan/htable/htable.h			\
	$(CCANDIR)/ccan/htable/htable_type.h		\
	$(CCANDIR)/ccan/ilog/ilog.h			\
	$(CCANDIR)/ccan/io/backend.h			\
	$(CCANDIR)/ccan/io/io.h				\
	$(CCANDIR)/ccan/io/io_plan.h			\
	$(CCANDIR)/ccan/isaac/isaac.h			\
	$(CCANDIR)/ccan/isaac/isaac64.h			\
	$(CCANDIR)/ccan/likely/likely.h			\
	$(CCANDIR)/ccan/list/list.h			\
	$(CCANDIR)/ccan/mem/mem.h			\
	$(CCANDIR)/ccan/noerr/noerr.h			\
	$(CCANDIR)/ccan/opt/opt.h			\
	$(CCANDIR)/ccan/opt/private.h			\
	$(CCANDIR)/ccan/order/order.h			\
	$(CCANDIR)/ccan/pipecmd/pipecmd.h		\
	$(CCANDIR)/ccan/ptrint/ptrint.h			\
	$(CCANDIR)/ccan/read_write_all/read_write_all.h	\
	$(CCANDIR)/ccan/short_types/short_types.h	\
	$(CCANDIR)/ccan/str/hex/hex.h			\
	$(CCANDIR)/ccan/str/str.h			\
	$(CCANDIR)/ccan/str/str_debug.h			\
	$(CCANDIR)/ccan/strmap/strmap.h			\
	$(CCANDIR)/ccan/structeq/structeq.h		\
	$(CCANDIR)/ccan/take/take.h			\
	$(CCANDIR)/ccan/tal/grab_file/grab_file.h	\
	$(CCANDIR)/ccan/tal/path/path.h			\
	$(CCANDIR)/ccan/tal/str/str.h			\
	$(CCANDIR)/ccan/tal/tal.h			\
	$(CCANDIR)/ccan/tcon/tcon.h			\
	$(CCANDIR)/ccan/time/time.h			\
	$(CCANDIR)/ccan/timer/timer.h			\
	$(CCANDIR)/ccan/typesafe_cb/typesafe_cb.h

BITCOIN_HEADERS := bitcoin/address.h		\
	bitcoin/base58.h			\
	bitcoin/block.h				\
	bitcoin/locktime.h			\
	bitcoin/privkey.h			\
	bitcoin/pubkey.h			\
	bitcoin/pullpush.h			\
	bitcoin/script.h			\
	bitcoin/shadouble.h			\
	bitcoin/signature.h			\
	bitcoin/tx.h				\
	bitcoin/varint.h

CORE_HEADERS := close_tx.h			\
	find_p2sh_out.h				\
	irc.h					\
	opt_bits.h				\
	overflows.h				\
	permute_tx.h				\
	protobuf_convert.h			\
	remove_dust.h				\
	utils.h					\
	version.h

GEN_HEADERS := 	gen_version.h			\
	lightning.pb-c.h

CDUMP_OBJS := ccan-cdump.o ccan-strmap.o

MANPAGES := doc/lightning-cli.1 \
	doc/lightning-delinvoice.7 \
	doc/lightning-getroute.7 \
	doc/lightning-invoice.7 \
	doc/lightning-listinvoice.7 \
	doc/lightning-sendpay.7 \
	doc/lightning-waitinvoice.7

PROGRAMS := $(TEST_PROGRAMS)

CWARNFLAGS := -Werror -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition
CDEBUGFLAGS := -g -fstack-protector
CFLAGS := $(CWARNFLAGS) $(CDEBUGFLAGS) -I $(CCANDIR) -I secp256k1/include/ -I . $(FEATURES)

LDLIBS := -lprotobuf-c -lgmp -lsodium -lbase58 -lsqlite3
$(PROGRAMS): CFLAGS+=-I.

default: $(PROGRAMS) $(MANPAGES) daemon-all

# Git doesn't maintain timestamps, so we only regen if git says we should.
CHANGED_FROM_GIT = [ x"`git log $@ | head -n1`" != x"`git log $< | head -n1`" -o x"`git diff $<`" != x"" ]

$(MANPAGES): doc/%: doc/%.txt
	@if $(CHANGED_FROM_GIT); then echo a2x --format=manpage $<; a2x --format=manpage $<; else touch $@; fi

# Everything depends on the CCAN headers.
$(CCAN_OBJS) $(CDUMP_OBJS) $(HELPER_OBJS) $(BITCOIN_OBJS) $(TEST_PROGRAMS:=.o) ccan/ccan/cdump/tools/cdump-enumstr.o: $(CCAN_HEADERS)

# Except for CCAN, everything depends on bitcoin/ and core headers.
$(HELPER_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(TEST_PROGRAMS:=.o): $(BITCOIN_HEADERS) $(CORE_HEADERS) $(CCAN_HEADERS) $(GEN_HEADERS)

test-protocol: test/test_protocol
	set -e; TMP=`mktemp`; [ -n "$(NO_VALGRIND)" ] || PREFIX="valgrind -q --error-exitcode=7"; for f in test/commits/*.script; do if ! $$PREFIX test/test_protocol < $$f > $$TMP; then echo "test/test_protocol < $$f FAILED" >&2; exit 1; fi; diff -u $$TMP $$f.expected; done; rm $$TMP

doc/protocol-%.svg: test/test_protocol
	test/test_protocol --svg < test/commits/$*.script > $@

protocol-diagrams: $(patsubst %.script, doc/protocol-%.svg, $(notdir $(wildcard test/commits/*.script)))

check: test-protocol bitcoin-tests

include bitcoin/Makefile

# Keep includes in alpha order.
check-src-include-order/%: %
	@if [ "$$(grep '^#include' < $<)" != "$$(grep '^#include' < $< | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; grep '^#include' < $<; echo VERSUS; grep '^#include' < $< | LC_ALL=C sort; exit 1; fi

# Keep includes in alpha order, after including "config.h"
check-hdr-include-order/%: %
	@if [ "$$(grep '^#include' < $< | head -n1)" != '#include "config.h"' ]; then echo "$<:1: doesn't include config.h first"; exit 1; fi
	@if [ "$$(grep '^#include' < $< | tail -n +2)" != "$$(grep '^#include' < $< | tail -n +2 | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; exit 1; fi

# Make sure Makefile includes all headers.
check-makefile: check-daemon-makefile
	@if [ "`echo bitcoin/*.h`" != "$(BITCOIN_HEADERS)" ]; then echo BITCOIN_HEADERS incorrect; exit 1; fi
	@if [ x"`ls *.h | grep -v ^gen_ | fgrep -v lightning.pb-c.h | tr '\n' ' '`" != x"$(CORE_HEADERS) " ]; then echo CORE_HEADERS incorrect; exit 1; fi
	@if [ x"$(CCANDIR)/config.h `find $(CCANDIR)/ccan -name '*.h' | grep -v /test/ | LC_ALL=C sort | tr '\n' ' '`" != x"$(CCAN_HEADERS) " ]; then echo CCAN_HEADERS incorrect; exit 1; fi

# Any mention of BOLT# must be followed by an exact quote, modulo whitepace.
check-source-bolt: check-bolt
	@if [ ! -d $(BOLTDIR) ]; then echo Not checking BOLT references: BOLTDIR $(BOLTDIR) does not exist >&2; else rm -rf .tmp.lightningrfc; git clone -q -b $(BOLTVERSION) $(BOLTDIR) .tmp.lightningrfc && ./check-bolt .tmp.lightningrfc $(CORE_SRC) $(BITCOIN_SRC) $(DAEMON_SRC) $(CORE_HEADERS) $(BITCOIN_HEADERS) $(DAEMON_HEADERS) $(TEST_PROGRAMS:=.c); fi

check-bolt: check-bolt.o $(CCAN_OBJS)

check-bolt.o: $(CCAN_HEADERS)

check-source: check-makefile check-source-bolt		\
	$(CORE_SRC:%=check-src-include-order/%)		\
	$(BITCOIN_SRC:%=check-src-include-order/%)	\
	$(CORE_HEADERS:%=check-hdr-include-order/%)	\
	$(BITCOIN_HEADERS:%=check-hdr-include-order/%)

full-check: check $(TEST_PROGRAMS) check-source

TAGS: FORCE
	$(RM) TAGS; find * -name '*.[ch]' | xargs etags --append
FORCE::

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

# We build a static libsecpk1, since we need ecdh
# (and it's not API stable yet!).
libsecp256k1.a: secp256k1/libsecp256k1.la

secp256k1/libsecp256k1.la:
	cd secp256k1 && ./autogen.sh && ./configure --enable-static=yes --enable-shared=no --enable-tests=no --enable-experimental=yes --enable-module-ecdh=yes --libdir=`pwd`/..
	$(MAKE) -C secp256k1 install-exec

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	@if $(CHANGED_FROM_GIT); then echo $(PROTOCC) lightning.proto --c_out=.; $(PROTOCC) lightning.proto --c_out=.; else touch $@; fi

$(TEST_PROGRAMS): % : %.o $(BITCOIN_OBJS) $(CCAN_OBJS) utils.o version.o libsecp256k1.a

ccan/config.h: ccan/tools/configurator/configurator
	if $< > $@.new; then mv $@.new $@; else rm $@.new; exit 1; fi

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

gen_version.h: FORCE
	@(echo "#define VERSION \"`git describe --always --dirty`\"" && echo "#define VERSION_NAME \"$(NAME)\"" && echo "#define BUILD_FEATURES \"$(FEATURES)\"") > $@.new
	@if cmp $@.new $@ >/dev/null 2>&2; then rm -f $@.new; else mv $@.new $@; echo Version updated; fi

version.o: gen_version.h

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | sed s,/_info,, | sort` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan describe` >> ccan/README
	$(RM) -r ccan.old

update-secp256k1:
	mv secp256k1 secp256k1.old
	cp -a ../secp256k1 secp256k1
	rm -rf secp256k1/.git
	grep -v '^secp256k1 version:' secp256k1.old/README > secp256k1/README
	echo secp256k1 version: `git -C ../secp256k1 describe 2>/dev/null || git -C ../secp256k1 show HEAD --format=%H` >> secp256k1/README
	$(RM) -r secp256k1.old

distclean: clean
	$(MAKE) -C secp256k1/ distclean || true
	$(RM) libsecp256k1.a secp256k1/libsecp256k1.la

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'
	$(RM) lightning.pb-c.c lightning.pb-c.h
	$(RM) doc/deployable-lightning.pdf
	$(RM) $(MANPAGES)

clean: daemon-clean
	$(MAKE) -C secp256k1/ clean || true
	$(RM) libsecp256k1.{a,la}
	$(RM) $(PROGRAMS)
	$(RM) bitcoin/*.o *.o $(PROGRAMS:=.o) $(CCAN_OBJS)
	$(RM) ccan/config.h gen_*.h
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr.o
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

include daemon/Makefile

ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-path.o: $(CCANDIR)/ccan/tal/path/path.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-asort.o: $(CCANDIR)/ccan/asort/asort.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-ripemd160.o: $(CCANDIR)/ccan/crypto/ripemd160/ripemd160.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-cdump.o: $(CCANDIR)/ccan/cdump/cdump.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-strmap.o: $(CCANDIR)/ccan/strmap/strmap.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-siphash24.o: $(CCANDIR)/ccan/crypto/siphash24/siphash24.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-ilog.o: $(CCANDIR)/ccan/ilog/ilog.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac.o: $(CCANDIR)/ccan/isaac/isaac.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-pipecmd.o: $(CCANDIR)/ccan/pipecmd/pipecmd.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-mem.o: $(CCANDIR)/ccan/mem/mem.c
	$(CC) $(CFLAGS) -c -o $@ $<
