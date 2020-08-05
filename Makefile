#! /usr/bin/make

# Extract version from git, or if we're from a zipfile, use dirname
VERSION=$(shell git describe --always --dirty=-modded --abbrev=7 2>/dev/null || pwd | sed -n 's|.*/c\{0,1\}lightning-v\{0,1\}\([0-9a-f.rc]*\)$$|\1|gp')

ifeq ($(VERSION),)
$(error "ERROR: git is required for generating version information")
endif

# --quiet / -s means quiet, dammit!
ifeq ($(findstring s,$(word 1, $(MAKEFLAGS))),s)
ECHO := :
SUPPRESS_OUTPUT := > /dev/null
else
ECHO := echo
SUPPRESS_OUTPUT :=
endif

DISTRO=$(shell lsb_release -is 2>/dev/null || echo unknown)-$(shell lsb_release -rs 2>/dev/null || echo unknown)
PKGNAME = c-lightning

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../lightning-rfc/
BOLTVERSION := 9e8e29af9b9a922eb114b2c716205d0772946e56

-include config.vars

SORT=LC_ALL=C sort


ifeq ($V,1)
VERBOSE = $(ECHO) $(2); $(2)
else
VERBOSE = $(ECHO) $(1); $(2)
endif

ifneq ($(VALGRIND),0)
VG=VALGRIND=1 valgrind -q --error-exitcode=7
VG_TEST_ARGS = --track-origins=yes --leak-check=full --show-reachable=yes --errors-for-leak-kinds=all
endif

ifneq ($(ASAN),0)
SANITIZER_FLAGS=-fsanitize=address
else
SANITIZER_FLAGS=
endif

ifeq ($(DEVELOPER),1)
DEV_CFLAGS=-DCCAN_TAKE_DEBUG=1 -DCCAN_TAL_DEBUG=1 -DCCAN_JSON_OUT_DEBUG=1
else
DEV_CFLAGS=
endif

ifeq ($(COVERAGE),1)
COVFLAGS = --coverage
endif

ifeq ($(PIE),1)
PIE_CFLAGS=-fPIE -fPIC
PIE_LDFLAGS=-pie
endif

ifeq ($(COMPAT),1)
# We support compatibility with pre-0.6.
COMPAT_CFLAGS=-DCOMPAT_V052=1 -DCOMPAT_V060=1 -DCOMPAT_V061=1 -DCOMPAT_V062=1 -DCOMPAT_V070=1 -DCOMPAT_V072=1 -DCOMPAT_V073=1 -DCOMPAT_V080=1 -DCOMPAT_V081=1 -DCOMPAT_V082=1 -DCOMPAT_V090=1
endif

# Timeout shortly before the 600 second travis silence timeout
# (method=thread to support xdist)
PYTEST_OPTS := -v --timeout=550 --timeout_method=thread -p no:logging

# This is where we add new features as bitcoin adds them.
FEATURES :=

CCAN_OBJS :=					\
	ccan-asort.o				\
	ccan-autodata.o				\
	ccan-bitmap.o				\
	ccan-bitops.o				\
	ccan-breakpoint.o			\
	ccan-crc32c.o				\
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
	ccan-json_escape.o			\
	ccan-json_out.o				\
	ccan-list.o				\
	ccan-mem.o				\
	ccan-membuf.o				\
	ccan-noerr.o				\
	ccan-opt-helpers.o			\
	ccan-opt-parse.o			\
	ccan-opt-usage.o			\
	ccan-opt.o				\
	ccan-pipecmd.o				\
	ccan-ptr_valid.o			\
	ccan-rbuf.o				\
	ccan-read_write_all.o			\
	ccan-str-base32.o			\
	ccan-str-hex.o				\
	ccan-str.o				\
	ccan-strmap.o				\
	ccan-take.o				\
	ccan-tal-grab_file.o			\
	ccan-tal-link.o				\
	ccan-tal-path.o				\
	ccan-tal-str.o				\
	ccan-tal.o				\
	ccan-time.o				\
	ccan-timer.o				\
	ccan-utf8.o

CCAN_HEADERS :=						\
	$(CCANDIR)/config.h				\
	$(CCANDIR)/ccan/alignof/alignof.h		\
	$(CCANDIR)/ccan/array_size/array_size.h		\
	$(CCANDIR)/ccan/asort/asort.h			\
	$(CCANDIR)/ccan/autodata/autodata.h		\
	$(CCANDIR)/ccan/bitmap/bitmap.h			\
	$(CCANDIR)/ccan/bitops/bitops.h			\
	$(CCANDIR)/ccan/breakpoint/breakpoint.h		\
	$(CCANDIR)/ccan/build_assert/build_assert.h	\
	$(CCANDIR)/ccan/cast/cast.h			\
	$(CCANDIR)/ccan/cdump/cdump.h			\
	$(CCANDIR)/ccan/check_type/check_type.h		\
	$(CCANDIR)/ccan/compiler/compiler.h		\
	$(CCANDIR)/ccan/container_of/container_of.h	\
	$(CCANDIR)/ccan/cppmagic/cppmagic.h		\
	$(CCANDIR)/ccan/crc32c/crc32c.h			\
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
	$(CCANDIR)/ccan/json_escape/json_escape.h	\
	$(CCANDIR)/ccan/json_out/json_out.h		\
	$(CCANDIR)/ccan/likely/likely.h			\
	$(CCANDIR)/ccan/list/list.h			\
	$(CCANDIR)/ccan/mem/mem.h			\
	$(CCANDIR)/ccan/membuf/membuf.h			\
	$(CCANDIR)/ccan/noerr/noerr.h			\
	$(CCANDIR)/ccan/opt/opt.h			\
	$(CCANDIR)/ccan/opt/private.h			\
	$(CCANDIR)/ccan/order/order.h			\
	$(CCANDIR)/ccan/pipecmd/pipecmd.h		\
	$(CCANDIR)/ccan/ptr_valid/ptr_valid.h		\
	$(CCANDIR)/ccan/ptrint/ptrint.h			\
	$(CCANDIR)/ccan/rbuf/rbuf.h			\
	$(CCANDIR)/ccan/read_write_all/read_write_all.h	\
	$(CCANDIR)/ccan/short_types/short_types.h	\
	$(CCANDIR)/ccan/str/base32/base32.h		\
	$(CCANDIR)/ccan/str/hex/hex.h			\
	$(CCANDIR)/ccan/str/str.h			\
	$(CCANDIR)/ccan/str/str_debug.h			\
	$(CCANDIR)/ccan/strmap/strmap.h			\
	$(CCANDIR)/ccan/structeq/structeq.h		\
	$(CCANDIR)/ccan/take/take.h			\
	$(CCANDIR)/ccan/tal/grab_file/grab_file.h	\
	$(CCANDIR)/ccan/tal/link/link.h			\
	$(CCANDIR)/ccan/tal/path/path.h			\
	$(CCANDIR)/ccan/tal/str/str.h			\
	$(CCANDIR)/ccan/tal/tal.h			\
	$(CCANDIR)/ccan/tcon/tcon.h			\
	$(CCANDIR)/ccan/time/time.h			\
	$(CCANDIR)/ccan/timer/timer.h			\
	$(CCANDIR)/ccan/typesafe_cb/typesafe_cb.h	\
	$(CCANDIR)/ccan/utf8/utf8.h

CDUMP_OBJS := ccan-cdump.o ccan-strmap.o

BOLT_GEN := tools/generate-wire.py
WIRE_GEN := $(BOLT_GEN)
BOLT_DEPS := $(BOLT_GEN)

ALL_PROGRAMS =

CPPFLAGS += -DBINTOPKGLIBEXECDIR="\"$(shell sh tools/rel.sh $(bindir) $(pkglibexecdir))\""
CFLAGS = $(CPPFLAGS) $(CWARNFLAGS) $(CDEBUGFLAGS) $(COPTFLAGS) -I $(CCANDIR) $(EXTERNAL_INCLUDE_FLAGS) -I . -I/usr/local/include $(FEATURES) $(COVFLAGS) $(DEV_CFLAGS) -DSHACHAIN_BITS=48 -DJSMN_PARENT_LINKS $(PIE_CFLAGS) $(COMPAT_CFLAGS) -DBUILD_ELEMENTS=1
# If CFLAGS is already set in the environment of make (to whatever value, it
# does not matter) then it would export it to subprocesses with the above value
# we set, including CWARNFLAGS which by default contains -Wall -Werror. This
# breaks at least libwally-core which tries to switch off some warnings with
# -Wno-whatever. So, tell make to not export our CFLAGS to subprocesses.
unexport CFLAGS

# We can get configurator to run a different compile cmd to cross-configure.
CONFIGURATOR_CC := $(CC)

LDFLAGS += $(PIE_LDFLAGS) $(SANITIZER_FLAGS) $(COPTFLAGS)
ifeq ($(STATIC),1)
# For MacOS, Jacob Rapoport <jacob@rumblemonkey.com> changed this to:
#  -L/usr/local/lib -Wl,-lgmp -lsqlite3 -lz -Wl,-lm -lpthread -ldl $(COVFLAGS)
# But that doesn't static link.
LDLIBS = -L/usr/local/lib -Wl,-dn -lgmp -lsqlite3 -lz -Wl,-dy -lm -lpthread -ldl $(COVFLAGS)
else
LDLIBS = -L/usr/local/lib -lm -lgmp -lsqlite3 -lz $(COVFLAGS)
endif

# If we have the postgres client library we need to link against it as well
ifeq ($(HAVE_POSTGRES),1)
LDLIBS += -lpq
endif

default: show-flags all-programs all-test-programs doc-all

show-flags:
	@$(ECHO) "CC: $(CC) $(CFLAGS) -c -o"
	@$(ECHO) "LD: $(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) -o"

ccan/config.h: config.vars configure ccan/tools/configurator/configurator.c
	./configure --reconfigure

config.vars:
	@echo 'File config.vars not found: you must run ./configure before running make.' >&2
	@exit 1

%.o: %.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)

include external/Makefile
include bitcoin/Makefile
include common/Makefile
include wire/Makefile
include hsmd/Makefile
include gossipd/Makefile
include openingd/Makefile
include channeld/Makefile
include closingd/Makefile
include onchaind/Makefile
include connectd/Makefile
include lightningd/Makefile
include cli/Makefile
include doc/Makefile
include devtools/Makefile
include tools/Makefile
include plugins/Makefile
include tests/plugins/Makefile

# Generated from PLUGINS definition in plugins/Makefile
gen_list_of_builtin_plugins.h : plugins/Makefile Makefile
	@echo GEN $@
	@rm -f $@ || true
	@echo 'static const char *list_of_builtin_plugins[] = {' >> $@
	@echo '$(PLUGINS)' | sed 's@plugins/\([^ 	]*\)@"\1",@g'>> $@
	@echo 'NULL' >> $@
	@echo '};' >> $@

# Git doesn't maintain timestamps, so we only regen if git says we should.
CHANGED_FROM_GIT = [ x"`git log $@ | head -n1`" != x"`git log $< | head -n1`" -o x"`git diff $<`" != x"" ]

ifneq ($(TEST_GROUP_COUNT),)
PYTEST_OPTS += --test-group=$(TEST_GROUP) --test-group-count=$(TEST_GROUP_COUNT)
endif

# If we run the tests in parallel we can speed testing up by a lot, however we
# then don't exit on the first error, since that'd kill the other tester
# processes and result in loads in loads of output. So we only tell py.test to
# abort early if we aren't running in parallel.
ifneq ($(PYTEST_PAR),)
PYTEST_OPTS += -n=$(PYTEST_PAR)
else
PYTEST_OPTS += -x
endif

check-units:

check: check-units installcheck pytest

pytest: $(ALL_PROGRAMS)
ifeq ($(PYTEST),)
	@echo "py.test is required to run the integration tests, please install using 'pip3 install -r requirements.txt', and rerun 'configure'."
	exit 1
else
# Explicitly hand DEVELOPER and VALGRIND so you can override on make cmd line.
	PYTHONPATH=`pwd`/contrib/pyln-client:`pwd`/contrib/pyln-testing:`pwd`/contrib/pyln-proto/:$(PYTHONPATH) TEST_DEBUG=1 DEVELOPER=$(DEVELOPER) VALGRIND=$(VALGRIND) $(PYTEST) tests/ $(PYTEST_OPTS)
endif

# Keep includes in alpha order.
check-src-include-order/%: %
	@if [ "$$(grep '^#include' < $<)" != "$$(grep '^#include' < $< | $(SORT))" ]; then echo "$<:1: includes out of order"; grep '^#include' < $<; echo VERSUS; grep '^#include' < $< | $(SORT); exit 1; fi

# Keep includes in alpha order, after including "config.h"
check-hdr-include-order/%: %
	@if [ "$$(grep '^#include' < $< | head -n1)" != '#include "config.h"' ]; then echo "$<:1: doesn't include config.h first"; exit 1; fi
	@if [ "$$(grep '^#include' < $< | tail -n +2)" != "$$(grep '^#include' < $< | tail -n +2 | $(SORT))" ]; then echo "$<:1: includes out of order"; exit 1; fi

# Make sure Makefile includes all headers.
check-makefile:
	@if [ x"$(CCANDIR)/config.h `find $(CCANDIR)/ccan -name '*.h' | grep -v /test/ | $(SORT) | tr '\n' ' '`" != x"$(CCAN_HEADERS) " ]; then echo CCAN_HEADERS incorrect; exit 1; fi

# Experimental quotes quote the exact version.
ifeq ($(EXPERIMENTAL_FEATURES),1)
CHECK_BOLT_PREFIX=--prefix="BOLT-$(BOLTVERSION)"
else
CHECK_BOLT_PREFIX=
endif

# Any mention of BOLT# must be followed by an exact quote, modulo whitespace.
bolt-check/%: % bolt-precheck tools/check-bolt
	@if [ -d .tmp.lightningrfc ]; then tools/check-bolt $(CHECK_BOLT_PREFIX) .tmp.lightningrfc $<; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi

LOCAL_BOLTDIR=.tmp.lightningrfc

bolt-precheck:
	@[ -d $(BOLTDIR) ] || exit 0; set -e; if [ -z "$(BOLTVERSION)" ]; then rm -rf $(LOCAL_BOLTDIR); ln -sf $(BOLTDIR) $(LOCAL_BOLTDIR); exit 0; fi; [ "$$(git -C $(LOCAL_BOLTDIR) rev-list --max-count=1 HEAD 2>/dev/null)" != "$(BOLTVERSION)" ] || exit 0; rm -rf $(LOCAL_BOLTDIR) && git clone -q $(BOLTDIR) $(LOCAL_BOLTDIR) && cd $(LOCAL_BOLTDIR) && git checkout -q $(BOLTVERSION)

check-source-bolt: $(ALL_TEST_PROGRAMS:%=bolt-check/%.c)

check-whitespace/%: %
	@if grep -Hn '[ 	]$$' $<; then echo Extraneous whitespace found >&2; exit 1; fi

check-whitespace: check-whitespace/Makefile check-whitespace/tools/check-bolt.c $(ALL_TEST_PROGRAMS:%=check-whitespace/%.c)

check-markdown:
	@tools/check-markdown.sh

check-spelling:
	@tools/check-spelling.sh

PYSRC=$(shell git ls-files "*.py" | grep -v /text.py) contrib/pylightning/lightning-pay

check-python:
	@# E501 line too long (N > 79 characters)
	@# E731 do not assign a lambda expression, use a def
	@# W503: line break before binary operator
	@flake8 --ignore=E501,E731,W503 ${PYSRC}

	PYTHONPATH=contrib/pyln-client:$$PYTHONPATH $(PYTEST) contrib/pyln-client/
	PYTHONPATH=contrib/pyln-proto:$$PYTHONPATH $(PYTEST) contrib/pyln-proto/

check-includes:
	@tools/check-includes.sh

# cppcheck gets confused by list_for_each(head, i, list): thinks i is uninit.
.cppcheck-suppress:
	@git ls-files -- "*.c" "*.h" | grep -vE '^ccan/' | xargs grep -n '_for_each' | sed 's/\([^:]*:.*\):.*/uninitvar:\1/' > $@

check-cppcheck: .cppcheck-suppress
	@trap 'rm -f .cppcheck-suppress' 0; git ls-files -- "*.c" "*.h" | grep -vE '^ccan/' | xargs cppcheck -q --language=c --std=c11 --error-exitcode=1 --suppressions-list=.cppcheck-suppress --inline-suppr

check-shellcheck:
	@git ls-files -- "*.sh" | xargs shellcheck

check-setup_locale:
	@tools/check-setup_locale.sh

check-tmpctx:
	@if git grep -n 'tal_free[(]tmpctx)' | grep -Ev '^ccan/|/test/|^common/setup.c:|^common/utils.c:'; then echo "Don't free tmpctx!">&2; exit 1; fi

check-discouraged-functions:
	@if git grep -E "[^a-z_/](fgets|fputs|gets|scanf|sprintf)\(" -- "*.c" "*.h" ":(exclude)ccan/"; then exit 1; fi

# Don't access amount_msat and amount_sat members directly without a good reason
# since it risks overflow.
check-amount-access:
	@! (git grep -nE "(->|\.)(milli)?satoshis" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*" | grep -v '/* Raw:')
	@! git grep -nE "\\(struct amount_(m)?sat\\)" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*"

check-source: check-makefile check-source-bolt check-whitespace check-markdown check-spelling check-python check-includes check-cppcheck check-shellcheck check-setup_locale check-tmpctx check-discouraged-functions check-amount-access

full-check: check check-source

coverage/coverage.info: check pytest
	mkdir coverage || true
	lcov --capture --directory . --output-file coverage/coverage.info

coverage: coverage/coverage.info
	genhtml coverage/coverage.info --output-directory coverage

# We make libwallycore.la a dependency, so that it gets built normally, without ncc.
# Ncc can't handle the libwally source code (yet).
ncc: ${TARGET_DIR}/libwally-core-build/src/libwallycore.la
	$(MAKE) CC="ncc -ncgcc -ncld -ncfabs" AR=nccar LD=nccld

# Ignore test/ directories.
TAGS: FORCE
	$(RM) TAGS; find * -name test -type d -prune -o -name '*.[ch]' -print -o -name '*.py' -print | xargs etags --append
FORCE::

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

ALL_PROGRAMS += ccan/ccan/cdump/tools/cdump-enumstr
# Can't add to ALL_OBJS, as that makes a circular dep.
ccan/ccan/cdump/tools/cdump-enumstr.o: $(CCAN_HEADERS) Makefile

gen_version.h: FORCE
	@(echo "#define VERSION \"$(VERSION)\"" && echo "#define BUILD_FEATURES \"$(FEATURES)\"") > $@.new
	@if cmp $@.new $@ >/dev/null 2>&1; then rm -f $@.new; else mv $@.new $@; $(ECHO) Version updated; fi

# That forces this rule to be run every time, too.
gen_header_versions.h: tools/headerversions
	@tools/headerversions $@

# Rebuild the world if this changes.
ALL_GEN_HEADERS += gen_header_versions.h

# All binaries require the external libs, ccan and system library versions.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS): $(EXTERNAL_LIBS) $(CCAN_OBJS)

# Each test program depends on its own object.
$(ALL_TEST_PROGRAMS): %: %.o

# Without this rule, the (built-in) link line contains
# external/libwallycore.a directly, which causes a symbol clash (it
# uses some ccan modules internally).  We want to rely on -lwallycore etc.
# (as per EXTERNAL_LDLIBS) so we filter them out here.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS):
	@$(call VERBOSE, "ld $@", $(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) -o $@)

# Everything depends on the CCAN headers, and Makefile
$(CCAN_OBJS) $(CDUMP_OBJS): $(CCAN_HEADERS) Makefile

# Except for CCAN, we treat everything else as dependent on external/ bitcoin/ common/ wire/ and all generated headers, and Makefile
$(ALL_OBJS): $(BITCOIN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS) $(WIRE_HEADERS) $(ALL_GEN_HEADERS) $(EXTERNAL_HEADERS) Makefile

# We generate headers in two ways, so regen when either changes (or Makefile)
$(ALL_GEN_HEADERS): ccan/ccan/cdump/tools/cdump-enumstr $(WIRE_GEN) Makefile

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | sed s,/_info,, | $(SORT)` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ../ccan/doc/configurator.1 ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan describe` >> ccan/README
	$(RM) -r ccan.old
	$(RM) -r ccan/ccan/hash/ ccan/ccan/tal/talloc/	# Unnecessary deps

# Now ALL_PROGRAMS is fully populated, we can expand it.
all-programs: $(ALL_PROGRAMS)
all-test-programs: $(ALL_TEST_PROGRAMS)

distclean: clean
	$(RM) ccan/config.h config.vars

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'

clean:
	$(RM) $(CCAN_OBJS) $(CDUMP_OBJS) $(ALL_OBJS)
	$(RM) $(ALL_PROGRAMS) $(ALL_PROGRAMS:=.o)
	$(RM) $(ALL_TEST_PROGRAMS) $(ALL_TEST_PROGRAMS:=.o)
	$(RM) gen_*.h ccan/tools/configurator/configurator
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr.o
	find . -name '*gcda' -delete
	find . -name '*gcno' -delete
	find . -name '*.nccout' -delete

update-mocks: $(ALL_GEN_HEADERS)
update-mocks/%: %
	@MAKE=$(MAKE) tools/update-mocks.sh "$*" $(SUPPRESS_OUTPUT)

unittest/%: %
	$(VG) $(VG_TEST_ARGS) $* > /dev/null

# Installation directories
exec_prefix = $(PREFIX)
bindir = $(exec_prefix)/bin
libexecdir = $(exec_prefix)/libexec
pkglibexecdir = $(libexecdir)/$(PKGNAME)
plugindir = $(pkglibexecdir)/plugins
datadir = $(PREFIX)/share
docdir = $(datadir)/doc/$(PKGNAME)
mandir = $(datadir)/man
man1dir = $(mandir)/man1
man5dir = $(mandir)/man5
man7dir = $(mandir)/man7
man8dir = $(mandir)/man8

# Commands
MKDIR_P = mkdir -p
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# Tags needed by some package systems.
PRE_INSTALL = :
NORMAL_INSTALL = :
POST_INSTALL = :
PRE_UNINSTALL = :
NORMAL_UNINSTALL = :
POST_UNINSTALL = :

# Target to create directories.
installdirs:
	@$(NORMAL_INSTALL)
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(pkglibexecdir)
	$(MKDIR_P) $(DESTDIR)$(plugindir)
	$(MKDIR_P) $(DESTDIR)$(man1dir)
	$(MKDIR_P) $(DESTDIR)$(man5dir)
	$(MKDIR_P) $(DESTDIR)$(man7dir)
	$(MKDIR_P) $(DESTDIR)$(man8dir)
	$(MKDIR_P) $(DESTDIR)$(docdir)

# Programs to install in bindir and pkglibexecdir.
# TODO: $(EXEEXT) support for Windows?  Needs more coding for
# the individual Makefiles, however.
BIN_PROGRAMS = \
	       cli/lightning-cli \
	       lightningd/lightningd \
	       tools/lightning-hsmtool
PKGLIBEXEC_PROGRAMS = \
	       lightningd/lightning_channeld \
	       lightningd/lightning_closingd \
	       lightningd/lightning_connectd \
	       lightningd/lightning_gossipd \
	       lightningd/lightning_hsmd \
	       lightningd/lightning_onchaind \
	       lightningd/lightning_openingd

# $(PLUGINS) is defined in plugins/Makefile.

install-program: installdirs $(BIN_PROGRAMS) $(PKGLIBEXEC_PROGRAMS) $(PLUGINS)
	@$(NORMAL_INSTALL)
	$(INSTALL_PROGRAM) $(BIN_PROGRAMS) $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) $(PKGLIBEXEC_PROGRAMS) $(DESTDIR)$(pkglibexecdir)
	[ -z "$(PLUGINS)" ] || $(INSTALL_PROGRAM) $(PLUGINS) $(DESTDIR)$(plugindir)

MAN1PAGES = $(filter %.1,$(MANPAGES))
MAN5PAGES = $(filter %.5,$(MANPAGES))
MAN7PAGES = $(filter %.7,$(MANPAGES))
MAN8PAGES = $(filter %.8,$(MANPAGES))
DOC_DATA = README.md doc/INSTALL.md doc/HACKING.md LICENSE

install-data: installdirs $(MAN1PAGES) $(MAN5PAGES) $(MAN7PAGES) $(MAN8PAGES) $(DOC_DATA)
	@$(NORMAL_INSTALL)
	$(INSTALL_DATA) $(MAN1PAGES) $(DESTDIR)$(man1dir)
	$(INSTALL_DATA) $(MAN5PAGES) $(DESTDIR)$(man5dir)
	$(INSTALL_DATA) $(MAN7PAGES) $(DESTDIR)$(man7dir)
	$(INSTALL_DATA) $(MAN8PAGES) $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) $(DOC_DATA) $(DESTDIR)$(docdir)

install: install-program install-data

uninstall:
	@$(NORMAL_UNINSTALL)
	@for f in $(BIN_PROGRAMS); do \
	  $(ECHO) rm -f $(DESTDIR)$(bindir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(bindir)/`basename $$f`; \
	done
	@for f in $(PLUGINS); do \
	  $(ECHO) rm -f $(DESTDIR)$(plugindir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(plugindir)/`basename $$f`; \
	done
	@for f in $(PKGLIBEXEC_PROGRAMS); do \
	  $(ECHO) rm -f $(DESTDIR)$(pkglibexecdir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(pkglibexecdir)/`basename $$f`; \
	done
	@for f in $(MAN1PAGES); do \
	  $(ECHO) rm -f $(DESTDIR)$(man1dir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(man1dir)/`basename $$f`; \
	done
	@for f in $(MAN5PAGES); do \
	  $(ECHO) rm -f $(DESTDIR)$(man5dir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(man5dir)/`basename $$f`; \
	done
	@for f in $(MAN7PAGES); do \
	  $(ECHO) rm -f $(DESTDIR)$(man7dir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(man7dir)/`basename $$f`; \
	done
	@for f in $(MAN8PAGES); do \
	  $(ECHO) rm -f $(DESTDIR)$(man8dir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(man8dir)/`basename $$f`; \
	done
	@for f in $(DOC_DATA); do \
	  $(ECHO) rm -f $(DESTDIR)$(docdir)/`basename $$f`; \
	  rm -f $(DESTDIR)$(docdir)/`basename $$f`; \
	done

installcheck: all-programs
	@rm -rf testinstall || true
	$(MAKE) DESTDIR=$$(pwd)/testinstall install
	testinstall$(bindir)/lightningd --test-daemons-only --lightning-dir=testinstall
	$(MAKE) DESTDIR=$$(pwd)/testinstall uninstall
	@if test `find testinstall '!' -type d | wc -l` -ne 0; then \
		echo 'make uninstall left some files in testinstall directory!'; \
		exit 1; \
	fi
	@rm -rf testinstall || true

.PHONY: installdirs install-program install-data install uninstall \
	installcheck ncc bin-tarball show-flags

# Make a tarball of opt/clightning/, optionally with label for distribution.
bin-tarball: clightning-$(VERSION)-$(DISTRO).tar.xz
clightning-$(VERSION)-$(DISTRO).tar.xz: DESTDIR=$(shell pwd)/
clightning-$(VERSION)-$(DISTRO).tar.xz: prefix=opt/clightning
clightning-$(VERSION)-$(DISTRO).tar.xz: install
	trap "rm -rf opt" 0; tar cvfa $@ opt/

ccan-breakpoint.o: $(CCANDIR)/ccan/breakpoint/breakpoint.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-tal-link.o: $(CCANDIR)/ccan/tal/link/link.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-tal-path.o: $(CCANDIR)/ccan/tal/path/path.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-asort.o: $(CCANDIR)/ccan/asort/asort.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-autodata.o: $(CCANDIR)/ccan/autodata/autodata.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-ptr_valid.o: $(CCANDIR)/ccan/ptr_valid/ptr_valid.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-str-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crc32c.o: $(CCANDIR)/ccan/crc32c/crc32c.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crypto-hmac.o: $(CCANDIR)/ccan/crypto/hmac_sha256/hmac_sha256.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crypto-hkdf.o: $(CCANDIR)/ccan/crypto/hkdf_sha256/hkdf_sha256.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crypto-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	@$(call VERBOSE, "cc $< -DSHACHAIN_BITS=48", $(CC) $(CFLAGS) -DSHACHAIN_BITS=48 -c -o $@ $<)
ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crypto-ripemd160.o: $(CCANDIR)/ccan/crypto/ripemd160/ripemd160.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-cdump.o: $(CCANDIR)/ccan/cdump/cdump.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-strmap.o: $(CCANDIR)/ccan/strmap/strmap.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-crypto-siphash24.o: $(CCANDIR)/ccan/crypto/siphash24/siphash24.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-ilog.o: $(CCANDIR)/ccan/ilog/ilog.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-intmap.o: $(CCANDIR)/ccan/intmap/intmap.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-isaac.o: $(CCANDIR)/ccan/isaac/isaac.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-io-fdpass.o: $(CCANDIR)/ccan/io/fdpass/fdpass.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-pipecmd.o: $(CCANDIR)/ccan/pipecmd/pipecmd.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-mem.o: $(CCANDIR)/ccan/mem/mem.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-fdpass.o: $(CCANDIR)/ccan/fdpass/fdpass.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-bitops.o: $(CCANDIR)/ccan/bitops/bitops.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-rbuf.o: $(CCANDIR)/ccan/rbuf/rbuf.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-str-base32.o: $(CCANDIR)/ccan/str/base32/base32.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-utf8.o: $(CCANDIR)/ccan/utf8/utf8.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-bitmap.o: $(CCANDIR)/ccan/bitmap/bitmap.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-membuf.o: $(CCANDIR)/ccan/membuf/membuf.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-json_escape.o: $(CCANDIR)/ccan/json_escape/json_escape.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-json_out.o: $(CCANDIR)/ccan/json_out/json_out.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
