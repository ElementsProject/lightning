#! /usr/bin/make
NAME=Bitcoin Savings & Trust Daily Interest II

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../lightning-rfc/
BOLTVERSION := master

# If you don't have (working) valgrind.
#NO_VALGRIND := 1

ifneq ($(NO_VALGRIND),1)
VALGRIND=valgrind -q --error-exitcode=7
VALGRIND_TEST_ARGS = --track-origins=yes --leak-check=full --show-reachable=yes --errors-for-leak-kinds=all
endif

ifeq ($(COVERAGE),1)
COVFLAGS = --coverage
endif

# This is where we add new features as bitcoin adds them.
FEATURES :=

CCAN_OBJS :=					\
	ccan-asort.o				\
	ccan-autodata.o				\
	ccan-breakpoint.o			\
	ccan-crypto-hmac.o			\
	ccan-crypto-hkdf.o			\
	ccan-crypto-ripemd160.o			\
	ccan-crypto-sha256.o			\
	ccan-crypto-shachain.o			\
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

ALL_GEN_HEADERS += gen_version.h

CDUMP_OBJS := ccan-cdump.o ccan-strmap.o

WIRE_GEN := tools/generate-wire.py

ALL_PROGRAMS =

CWARNFLAGS := -Werror -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition
CDEBUGFLAGS := -std=gnu11 -g -fstack-protector
CFLAGS = $(CWARNFLAGS) $(CDEBUGFLAGS) -I $(CCANDIR) $(EXTERNAL_INCLUDE_FLAGS) -I . $(FEATURES) $(COVFLAGS) -DSHACHAIN_BITS=48

LDLIBS = -lgmp -lsqlite3 $(COVFLAGS)

default: all-programs all-test-programs

include external/Makefile
include bitcoin/Makefile
include common/Makefile
include wire/Makefile
include wallet/Makefile
include hsmd/Makefile
include gossipd/Makefile
include openingd/Makefile
include channeld/Makefile
include closingd/Makefile
include onchaind/Makefile
include lightningd/Makefile
include cli/Makefile
include test/Makefile
include doc/Makefile

# Git doesn't maintain timestamps, so we only regen if git says we should.
CHANGED_FROM_GIT = [ x"`git log $@ | head -n1`" != x"`git log $< | head -n1`" -o x"`git diff $<`" != x"" ]

check:
	$(MAKE) pytest

pytest: $(ALL_PROGRAMS)
	PYTHONPATH=contrib/pylightning python3 tests/test_lightningd.py -f

# Keep includes in alpha order.
check-src-include-order/%: %
	@if [ "$$(grep '^#include' < $<)" != "$$(grep '^#include' < $< | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; grep '^#include' < $<; echo VERSUS; grep '^#include' < $< | LC_ALL=C sort; exit 1; fi

# Keep includes in alpha order, after including "config.h"
check-hdr-include-order/%: %
	@if [ "$$(grep '^#include' < $< | head -n1)" != '#include "config.h"' ]; then echo "$<:1: doesn't include config.h first"; exit 1; fi
	@if [ "$$(grep '^#include' < $< | tail -n +2)" != "$$(grep '^#include' < $< | tail -n +2 | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; exit 1; fi

# Make sure Makefile includes all headers.
check-makefile:
	@if [ x"$(CCANDIR)/config.h `find $(CCANDIR)/ccan -name '*.h' | grep -v /test/ | LC_ALL=C sort | tr '\n' ' '`" != x"$(CCAN_HEADERS) " ]; then echo CCAN_HEADERS incorrect; exit 1; fi

# Any mention of BOLT# must be followed by an exact quote, modulo whitepace.
bolt-check/%: % bolt-precheck tools/check-bolt
	@[ ! -d .tmp.lightningrfc ] || tools/check-bolt .tmp.lightningrfc $<

bolt-precheck:
	@rm -rf .tmp.lightningrfc; if [ ! -d $(BOLTDIR) ]; then echo Not checking BOLT references: BOLTDIR $(BOLTDIR) does not exist >&2; exit 0; fi; set -e; if [ -n "$(BOLTVERSION)" ]; then git clone -q -b $(BOLTVERSION) $(BOLTDIR) .tmp.lightningrfc; else cp -a $(BOLTDIR) .tmp.lightningrfc; fi

check-source-bolt: $(ALL_TEST_PROGRAMS:%=bolt-check/%.c)

tools/check-bolt: tools/check-bolt.o $(CCAN_OBJS)

tools/check-bolt.o: $(CCAN_HEADERS)

check-whitespace/%: %
	@if grep -Hn '[ 	]$$' $<; then echo Extraneous whitespace found >&2; exit 1; fi

check-whitespace: check-whitespace/Makefile check-whitespace/tools/check-bolt.c $(ALL_TEST_PROGRAMS:%=check-whitespace/%.c)

check-source: check-makefile check-source-bolt check-whitespace

full-check: check check-source

coverage/coverage.info: check pytest
	mkdir coverage || true
	lcov --capture --directory . --output-file coverage/coverage.info

coverage: coverage/coverage.info
	genhtml coverage/coverage.info --output-directory coverage

# Ignore test/ directories.
TAGS: FORCE
	$(RM) TAGS; find * -name test -type d -prune -o -name '*.[ch]' -print | xargs etags --append
FORCE::

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

ALL_PROGRAMS += ccan/ccan/cdump/tools/cdump-enumstr
# Can't add to ALL_OBJS, as that makes a circular dep.
ccan/ccan/cdump/tools/cdump-enumstr.o: $(CCAN_HEADERS)

ccan/config.h: ccan/tools/configurator/configurator
	if $< > $@.new; then mv $@.new $@; else rm $@.new; exit 1; fi

gen_version.h: FORCE
	@(echo "#define VERSION \"`git describe --always --dirty`\"" && echo "#define VERSION_NAME \"$(NAME)\"" && echo "#define BUILD_FEATURES \"$(FEATURES)\"") > $@.new
	@if cmp $@.new $@ >/dev/null 2>&2; then rm -f $@.new; else mv $@.new $@; echo Version updated; fi

# All binaries require the external libs, ccan
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS): $(EXTERNAL_LIBS) $(CCAN_OBJS)

# Each test program depends on its own object.
$(ALL_TEST_PROGRAMS): %: %.o

# Without this rule, the (built-in) link line contains
# external/libwallycore.a directly, which causes a symbol clash (it
# uses some ccan modules internally).  We want to rely on -lwallycore etc.
# (as per EXTERNAL_LDLIBS) so we filter them out here.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS):
	$(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) -o $@

# Everything depends on the CCAN headers.
$(CCAN_OBJS) $(CDUMP_OBJS): $(CCAN_HEADERS)

# Except for CCAN, we treat everything else as dependent on external/ bitcoin/ common/ wire/ and all generated headers.
$(ALL_OBJS): $(BITCOIN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS) $(WIRE_HEADERS) $(ALL_GEN_HEADERS) $(EXTERNAL_HEADERS)

# We generate headers in two ways, so regen when either changes.
$(ALL_GEN_HEADERS): ccan/ccan/cdump/tools/cdump-enumstr $(WIRE_GEN)

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | sed s,/_info,, | sort` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan describe` >> ccan/README
	$(RM) -r ccan.old

# Now ALL_PROGRAMS is fully populated, we can expand it.
all-programs: $(ALL_PROGRAMS)
all-test-programs: $(ALL_TEST_PROGRAMS)

distclean: clean

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'

clean: wire-clean
	$(RM) $(CCAN_OBJS) $(CDUMP_OBJS) $(ALL_OBJS)
	$(RM) $(ALL_PROGRAMS) $(ALL_PROGRAMS:=.o)
	$(RM) $(ALL_TEST_PROGRAMS) $(ALL_TEST_PROGRAMS:=.o)
	$(RM) ccan/config.h gen_*.h
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr.o
	$(RM) check-bolt tools/check-bolt tools/*.o
	find . -name '*gcda' -delete
	find . -name '*gcno' -delete

update-mocks/%: %
	@tools/update-mocks.sh "$*"

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
ccan-crypto-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
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
