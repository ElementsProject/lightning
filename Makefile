#! /usr/bin/make
NAME=Bitcoin Savings & Trust Daily Interest II

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../lightning-rfc/
BOLTVERSION := master

# If you don't have (working) valgrind.
#NO_VALGRIND := 1

ifneq ($(NO_VALGRIND),1)
VALGRIND=valgrind -q --error-exitcode=7
VALGRIND_TEST_ARGS = --track-origins=yes --leak-check=full --show-reachable=yes
endif

ifeq ($(COVERAGE),1)
COVFLAGS = --coverage
endif

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
	opt_bits.c				\
	type_to_string.c			\
	utils.c					\
	version.c

CORE_OBJS := $(CORE_SRC:.c=.o)

CORE_TX_SRC :=					\
	close_tx.c				\
	find_p2sh_out.c				\
	permute_tx.c

CORE_TX_OBJS := $(CORE_TX_SRC:.c=.o)

CORE_PROTOBUF_SRC :=				\
	lightning.pb-c.c			\
	protobuf_convert.c

CORE_PROTOBUF_OBJS := $(CORE_PROTOBUF_SRC:.c=.o)

CCAN_OBJS :=					\
	ccan-asort.o				\
	ccan-autodata.o				\
	ccan-breakpoint.o			\
	ccan-crypto-hmac.o			\
	ccan-crypto-hkdf.o			\
	ccan-crypto-ripemd160.o			\
	ccan-crypto-sha256.o			\
	ccan-crypto-siphash24.o			\
	ccan-err.o				\
	ccan-fdpass.o				\
	ccan-htable.o				\
	ccan-ilog.o				\
	ccan-io-io.o				\
	ccan-intmap.o				\
	ccan-io-poll.o				\
	ccan-io-fdpass.o			\
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

CCAN_SHACHAIN48_OBJ := ccan-crypto-shachain-48.o

CCAN_HEADERS :=						\
	$(CCANDIR)/config.h				\
	$(CCANDIR)/ccan/alignof/alignof.h		\
	$(CCANDIR)/ccan/array_size/array_size.h		\
	$(CCANDIR)/ccan/asort/asort.h			\
	$(CCANDIR)/ccan/autodata/autodata.h		\
	$(CCANDIR)/ccan/breakpoint/breakpoint.h		\
	$(CCANDIR)/ccan/build_assert/build_assert.h	\
	$(CCANDIR)/ccan/cast/cast.h			\
	$(CCANDIR)/ccan/cdump/cdump.h			\
	$(CCANDIR)/ccan/check_type/check_type.h		\
	$(CCANDIR)/ccan/compiler/compiler.h		\
	$(CCANDIR)/ccan/container_of/container_of.h	\
	$(CCANDIR)/ccan/cppmagic/cppmagic.h		\
	$(CCANDIR)/ccan/crypto/hkdf_sha256/hkdf_sha256.h \
	$(CCANDIR)/ccan/crypto/hmac_sha256/hmac_sha256.h \
	$(CCANDIR)/ccan/crypto/ripemd160/ripemd160.h	\
	$(CCANDIR)/ccan/crypto/sha256/sha256.h		\
	$(CCANDIR)/ccan/crypto/shachain/shachain.h	\
	$(CCANDIR)/ccan/crypto/siphash24/siphash24.h	\
	$(CCANDIR)/ccan/endian/endian.h			\
	$(CCANDIR)/ccan/err/err.h			\
	$(CCANDIR)/ccan/fdpass/fdpass.h			\
	$(CCANDIR)/ccan/htable/htable.h			\
	$(CCANDIR)/ccan/htable/htable_type.h		\
	$(CCANDIR)/ccan/ilog/ilog.h			\
	$(CCANDIR)/ccan/intmap/intmap.h			\
	$(CCANDIR)/ccan/io/backend.h			\
	$(CCANDIR)/ccan/io/fdpass/fdpass.h		\
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
	$(CCANDIR)/ccan/ptr_valid/ptr_valid.h		\
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
	bitcoin/preimage.h			\
	bitcoin/privkey.h			\
	bitcoin/pubkey.h			\
	bitcoin/pullpush.h			\
	bitcoin/script.h			\
	bitcoin/shadouble.h			\
	bitcoin/signature.h			\
	bitcoin/tx.h				\
	bitcoin/varint.h

CORE_TX_HEADERS := close_tx.h			\
	find_p2sh_out.h				\
	permute_tx.h				\
	remove_dust.h

CORE_HEADERS := irc.h				\
	opt_bits.h				\
	overflows.h				\
	protobuf_convert.h			\
	type_to_string.h			\
	utils.h					\
	version.h

GEN_HEADERS := 	gen_version.h			\
	lightning.pb-c.h

LIBSODIUM_HEADERS := libsodium/src/libsodium/include/sodium.h
LIBWALLY_HEADERS := libwally-core/include/wally_bip32.h		\
			libwally-core/include/wally_core.h	\
			libwally-core/include/wally_crypto.h
LIBSECP_HEADERS := libwally-core/src/secp256k1/include/secp256k1_ecdh.h		\
		libwally-core/src/secp256k1/include/secp256k1.h

CDUMP_OBJS := ccan-cdump.o ccan-strmap.o

WIRE_GEN := tools/generate-wire.py

PROGRAMS := $(TEST_PROGRAMS)

CWARNFLAGS := -Werror -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition
CDEBUGFLAGS := -g -fstack-protector
CFLAGS := $(CWARNFLAGS) $(CDEBUGFLAGS) -I $(CCANDIR) -I libwally-core/src/secp256k1/include/ -I libwally-core/include/ -I libsodium/src/libsodium/include/ -I . $(FEATURES) $(COVFLAGS) -DSHACHAIN_BITS=48

LDLIBS := -lprotobuf-c -lgmp -lsqlite3 $(COVFLAGS)
$(PROGRAMS): CFLAGS+=-I.

default: $(PROGRAMS) doc-all daemon-all

include doc/Makefile
include bitcoin/Makefile
include wire/Makefile
include wallet/Makefile
include lightningd/Makefile

# Git doesn't maintain timestamps, so we only regen if git says we should.
CHANGED_FROM_GIT = [ x"`git log $@ | head -n1`" != x"`git log $< | head -n1`" -o x"`git diff $<`" != x"" ]

# Everything depends on the CCAN headers.
$(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(CDUMP_OBJS) $(HELPER_OBJS) $(BITCOIN_OBJS) $(TEST_PROGRAMS:=.o) ccan/ccan/cdump/tools/cdump-enumstr.o: $(CCAN_HEADERS)

# Except for CCAN, everything depends on bitcoin/ and core headers.
$(HELPER_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(CORE_PROTOBUF_OBJS) $(BITCOIN_OBJS) $(LIBBASE58_OBJS) $(WIRE_OBJS) $(TEST_PROGRAMS:=.o): $(BITCOIN_HEADERS) $(CORE_HEADERS) $(CCAN_HEADERS) $(GEN_HEADERS) $(LIBBASE58_HEADERS) $(LIBSODIUM_HEADERS) $(LIBWALLY_HEADERS)

test-protocol: test/test_protocol
	set -e; TMP=`mktemp`; for f in test/commits/*.script; do if ! $(VALGRIND) test/test_protocol < $$f > $$TMP; then echo "test/test_protocol < $$f FAILED" >&2; exit 1; fi; diff -u $$TMP $$f.expected; done; rm $$TMP

check: test-protocol
	$(MAKE) pytest

pytest: daemon/lightningd daemon/lightning-cli lightningd-all
	PYTHONPATH=contrib/pylightning python3 tests/test_lightningd.py -f

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
	@if [ x"`ls *.h | grep -v ^gen_ | fgrep -v lightning.pb-c.h`" != x"`echo $(CORE_HEADERS) $(CORE_TX_HEADERS) | tr ' ' '\n' | LC_ALL=C sort`" ]; then echo CORE_HEADERS incorrect; exit 1; fi
	@if [ x"$(CCANDIR)/config.h `find $(CCANDIR)/ccan -name '*.h' | grep -v /test/ | LC_ALL=C sort | tr '\n' ' '`" != x"$(CCAN_HEADERS) " ]; then echo CCAN_HEADERS incorrect; exit 1; fi

# Any mention of BOLT# must be followed by an exact quote, modulo whitepace.
bolt-check/%: % bolt-precheck check-bolt
	@[ ! -d .tmp.lightningrfc ] || ./check-bolt .tmp.lightningrfc $<

bolt-precheck:
	@rm -rf .tmp.lightningrfc; if [ ! -d $(BOLTDIR) ]; then echo Not checking BOLT references: BOLTDIR $(BOLTDIR) does not exist >&2; exit 0; fi; set -e; if [ -n "$(BOLTVERSION)" ]; then git clone -q -b $(BOLTVERSION) $(BOLTDIR) .tmp.lightningrfc; else cp -a $(BOLTDIR) .tmp.lightningrfc; fi

check-source-bolt: $(CORE_SRC:%=bolt-check/%) $(CORE_TX_SRC:%=bolt-check/%) $(CORE_PROTOBUF_SRC:%=bolt-check/%) $(CORE_HEADERS:%=bolt-check/%) $(TEST_PROGRAMS:%=bolt-check/%.c)

check-bolt: check-bolt.o $(CCAN_OBJS)

check-bolt.o: $(CCAN_HEADERS)

check-whitespace/%: %
	@if grep -Hn '[ 	]$$' $<; then echo Extraneous whitespace found >&2; exit 1; fi

check-whitespace: check-whitespace/Makefile check-whitespace/check-bolt.c $(CORE_SRC:%=check-whitespace/%) $(CORE_TX_SRC:%=check-whitespace/%) $(CORE_PROTOBUF_SRC:%=check-whitespace/%) $(CORE_HEADERS:%=check-whitespace/%)

check-source: check-makefile check-source-bolt check-whitespace	\
	$(CORE_SRC:%=check-src-include-order/%)			\
	$(CORE_TX_SRC:%=check-src-include-order/%)		\
	$(CORE_PROTOBUF_SRC:%=check-src-include-order/%)	\
	$(BITCOIN_SRC:%=check-src-include-order/%)		\
	$(CORE_HEADERS:%=check-hdr-include-order/%)		\
	$(CORE_TX_HEADERS:%=check-hdr-include-order/%)		\
	$(BITCOIN_HEADERS:%=check-hdr-include-order/%)

full-check: check $(TEST_PROGRAMS) check-source

coverage/coverage.info: check $(TEST_PROGRAMS) pytest
	mkdir coverage || true
	lcov --capture --directory . --output-file coverage/coverage.info

coverage: coverage/coverage.info
	genhtml coverage/coverage.info --output-directory coverage

# Ignore test/ directories.
TAGS: FORCE
	$(RM) TAGS; find * -name test -type d -prune -o -name '*.[ch]' -print | xargs etags --append
FORCE::

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

# We build libsodium, since Ubuntu xenial has one too old.
libsodium.a: libsodium/src/libsodium/libsodium.la
	$(MAKE) -C libsodium install-exec

libsodium/src/libsodium/include/sodium.h:
	git submodule update libsodium
	[ -f $@ ] || git submodule update --init libsodium

libsodium/src/libsodium/libsodium.la: libsodium/src/libsodium/include/sodium.h
	cd libsodium && ./autogen.sh && ./configure CC="$(CC)" --enable-static=yes --enable-shared=no --enable-tests=no --libdir=`pwd`/.. && $(MAKE)

# libsecp included in libwally.
# Wildcards here are magic.  See http://stackoverflow.com/questions/2973445/gnu-makefile-rule-generating-a-few-targets-from-a-single-source-file
libsecp256k1.% libwallycore.%: libwally-core/src/secp256k1/libsecp256k1.la libwally-core/src/libwallycore.la
	$(MAKE) -C libwally-core install-exec

libwally-core/src/libwallycore.% libwally-core/src/secp256k1/libsecp256k1.%: $(LIBWALLY_HEADERS) $(LIBSECP_HEADERS)
	cd libwally-core && ./tools/autogen.sh && ./configure CC="$(CC)" --enable-static=yes --enable-shared=no --libdir=`pwd`/.. && $(MAKE)

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	@if $(CHANGED_FROM_GIT); then echo $(PROTOCC) lightning.proto --c_out=.; $(PROTOCC) lightning.proto --c_out=.; else touch $@; fi

$(TEST_PROGRAMS): % : %.o $(BITCOIN_OBJS) $(LIBBASE58_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) lightningd/sphinx.o utils.o version.o libwallycore.a libsecp256k1.a libsodium.a

ccan/config.h: ccan/tools/configurator/configurator
	if $< > $@.new; then mv $@.new $@; else rm $@.new; exit 1; fi

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
	$(RM) libsodium.a libsodium.la libsodium/libsodium.la
	$(RM) libwallycore.a libwallycore.la
	$(RM) libwally-core/src/secp256k1/libsecp256k1.la libwally-core/src/libwallycore.la
	cd libwally-core && tools/cleanup.sh

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'
	$(RM) lightning.pb-c.c lightning.pb-c.h

clean: daemon-clean wire-clean
	$(MAKE) -C secp256k1/ clean || true
	$(RM) libsecp256k1.{a,la}
	$(RM) libsodium.{a,la}
	$(RM) $(PROGRAMS)
	$(RM) bitcoin/*.o *.o $(PROGRAMS:=.o) $(CCAN_OBJS)
	$(RM) ccan/config.h gen_*.h
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr.o
	find . -name '*gcda' -delete
	find . -name '*gcno' -delete

include daemon/Makefile

update-mocks/%: %
	@set -e; BASE=/tmp/mocktmp.$$$$.`echo $* | tr / _`; trap "rm -f $$BASE.*" EXIT; \
	START=`fgrep -n '/* AUTOGENERATED MOCKS START */' $< | cut -d: -f1`;\
	END=`fgrep -n '/* AUTOGENERATED MOCKS END */' $< | cut -d: -f1`; \
	if [ -n "$$START" ]; then \
	  echo $<: ; \
	  head -n $$START $< > $$BASE.new; \
	  (cat $$BASE.new; tail -n +$$END $<) > $$BASE.test.c; \
	  if ! $(CC) $(CFLAGS) $$BASE.test.c -o $$BASE.out $(HELPER_OBJS) $(CCAN_OBJS) $(LDLIBS) 2>$$BASE.err; then \
	    test/scripts/mockup.sh < $$BASE.err >> $$BASE.new; \
	    sed -n 's,.*Generated stub for \(.*\) .*,\t\1,p' < $$BASE.new; \
          fi; \
	  tail -n +$$END $< >> $$BASE.new; mv $$BASE.new $<; \
	fi

test/test_sphinx: libsodium.a

unittest/%: %
	$(VALGRIND) $(VALGRIND_TEST_ARGS) $*

ccan-breakpoint.o: $(CCANDIR)/ccan/breakpoint/breakpoint.c
	$(CC) $(CFLAGS) -c -o $@ $<
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
ccan-autodata.o: $(CCANDIR)/ccan/autodata/autodata.c
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
ccan-crypto-hmac.o: $(CCANDIR)/ccan/crypto/hmac_sha256/hmac_sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-hkdf.o: $(CCANDIR)/ccan/crypto/hkdf_sha256/hkdf_sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-shachain-48.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	$(CC) $(CFLAGS) -DSHACHAIN_BITS=48 -c -o $@ $<
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
ccan-intmap.o: $(CCANDIR)/ccan/intmap/intmap.c
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
ccan-io-fdpass.o: $(CCANDIR)/ccan/io/fdpass/fdpass.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-pipecmd.o: $(CCANDIR)/ccan/pipecmd/pipecmd.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-mem.o: $(CCANDIR)/ccan/mem/mem.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-fdpass.o: $(CCANDIR)/ccan/fdpass/fdpass.c
	$(CC) $(CFLAGS) -c -o $@ $<
