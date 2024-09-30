#! /usr/bin/make

# Extract version from git, or if we're from a zipfile, use dirname
VERSION=$(shell git describe --tags --always --dirty=-modded --abbrev=7 2>/dev/null || pwd | sed -n 's|.*/c\{0,1\}lightning-v\{0,1\}\([0-9a-f.rc\-]*\)$$|\1|gp')

# Next release.
CLN_NEXT_VERSION := v24.11

# --quiet / -s means quiet, dammit!
ifeq ($(findstring s,$(word 1, $(MAKEFLAGS))),s)
ECHO := :
SUPPRESS_OUTPUT := > /dev/null
else
ECHO := echo
SUPPRESS_OUTPUT :=
endif

DISTRO=$(shell lsb_release -is 2>/dev/null || echo unknown)-$(shell lsb_release -rs 2>/dev/null || echo unknown)
OS=$(shell uname -s)
ARCH=$(shell uname -m)
# Changing this could break installs!
PKGNAME = c-lightning

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../bolts/
DEFAULT_BOLTVERSION := 5dec5eb84957d70c9fedf27173e78f1b0b6b0217
# Can be overridden on cmdline.
BOLTVERSION := $(DEFAULT_BOLTVERSION)

-include config.vars

SORT=LC_ALL=C sort


ifeq ($V,1)
VERBOSE = $(ECHO) '$(2)'; $(2)
else
VERBOSE = $(ECHO) $(1); $(2)
endif

ifneq ($(VALGRIND),0)
VG=VALGRIND=1 valgrind -q --error-exitcode=7
VG_TEST_ARGS = --track-origins=yes --leak-check=full --show-reachable=yes --errors-for-leak-kinds=all
endif

ifeq ($(DEBUGBUILD),1)
DEV_CFLAGS=-DCCAN_TAKE_DEBUG=1 -DCCAN_TAL_DEBUG=1 -DCCAN_JSON_OUT_DEBUG=1
else
DEV_CFLAGS=
endif

ifeq ($(COVERAGE),1)
COVFLAGS = --coverage
endif

ifeq ($(CLANG_COVERAGE),1)
COVFLAGS+=-fprofile-instr-generate -fcoverage-mapping
endif

ifeq ($(PIE),1)
PIE_CFLAGS=-fPIE -fPIC
PIE_LDFLAGS=-pie
endif

ifeq ($(COMPAT),1)
# We support compatibility with pre-0.6.
COMPAT_CFLAGS=-DCOMPAT_V052=1 -DCOMPAT_V060=1 -DCOMPAT_V061=1 -DCOMPAT_V062=1 -DCOMPAT_V070=1 -DCOMPAT_V072=1 -DCOMPAT_V073=1 -DCOMPAT_V080=1 -DCOMPAT_V081=1 -DCOMPAT_V082=1 -DCOMPAT_V090=1 -DCOMPAT_V0100=1 -DCOMPAT_V0121=1
endif

# (method=thread to support xdist)
PYTEST_OPTS := -v -p no:logging $(PYTEST_OPTS)
MY_CHECK_PYTHONPATH=$${PYTHONPATH}$${PYTHONPATH:+:}$(shell pwd)/contrib/pyln-client:$(shell pwd)/contrib/pyln-testing:$(shell pwd)/contrib/pyln-proto/:$(shell pwd)/contrib/pyln-spec/bolt1:$(shell pwd)/contrib/pyln-spec/bolt2:$(shell pwd)/contrib/pyln-spec/bolt4:$(shell pwd)/contrib/pyln-spec/bolt7:$(shell pwd)/contrib/pyln-grpc-proto
# Collect generated python files to be excluded from lint checks
PYTHON_GENERATED= \
	contrib/pyln-grpc-proto/pyln/grpc/primitives_pb2.py \
	contrib/pyln-grpc-proto/pyln/grpc/node_pb2_grpc.py \
	contrib/pyln-grpc-proto/pyln/grpc/node_pb2.py \
	contrib/pyln-testing/pyln/testing/grpc2py.py

# Options to pass to cppcheck. Mostly used to exclude files that are
# generated with external tools that we don't have control over
CPPCHECK_OPTS=-q --language=c --std=c11 --error-exitcode=1 --suppressions-list=.cppcheck-suppress --inline-suppr

# This is where we add new features as bitcoin adds them.
FEATURES :=

CCAN_OBJS :=					\
	ccan-asort.o				\
	ccan-base64.o				\
	ccan-bitmap.o				\
	ccan-bitops.o				\
	ccan-breakpoint.o			\
	ccan-closefrom.o			\
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
	ccan-rune-coding.o			\
	ccan-rune-rune.o			\
	ccan-str-base32.o			\
	ccan-str-hex.o				\
	ccan-str.o				\
	ccan-strmap.o				\
	ccan-strset.o				\
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
	$(CCANDIR)/ccan/base64/base64.h			\
	$(CCANDIR)/ccan/bitmap/bitmap.h			\
	$(CCANDIR)/ccan/bitops/bitops.h			\
	$(CCANDIR)/ccan/breakpoint/breakpoint.h		\
	$(CCANDIR)/ccan/build_assert/build_assert.h	\
	$(CCANDIR)/ccan/cast/cast.h			\
	$(CCANDIR)/ccan/cdump/cdump.h			\
	$(CCANDIR)/ccan/check_type/check_type.h		\
	$(CCANDIR)/ccan/closefrom/closefrom.h		\
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
	$(CCANDIR)/ccan/graphql/graphql.h		\
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
	$(CCANDIR)/ccan/lqueue/lqueue.h			\
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
	$(CCANDIR)/ccan/rune/internal.h			\
	$(CCANDIR)/ccan/rune/rune.h			\
	$(CCANDIR)/ccan/short_types/short_types.h	\
	$(CCANDIR)/ccan/str/base32/base32.h		\
	$(CCANDIR)/ccan/str/hex/hex.h			\
	$(CCANDIR)/ccan/str/str.h			\
	$(CCANDIR)/ccan/str/str_debug.h			\
	$(CCANDIR)/ccan/strmap/strmap.h			\
	$(CCANDIR)/ccan/strset/strset.h			\
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

# If you use wiregen, you're dependent on the tool and its templates
WIRE_GEN_DEPS := $(WIRE_GEN) $(wildcard tools/gen/*_template)

# These are filled by individual Makefiles
ALL_PROGRAMS :=
ALL_TEST_PROGRAMS :=
ALL_TEST_GEN :=
ALL_FUZZ_TARGETS :=
ALL_C_SOURCES :=
ALL_C_HEADERS :=
# Extra (non C) targets that should be built by default.
DEFAULT_TARGETS :=

# M1 macos machines with homebrew will install the native libraries in
# /opt/homebrew instead of /usr/local, most likely because they
# emulate x86_64 compatibility via Rosetta, and wanting to keep the
# libraries separate. This however means we also need to switch out
# the paths accordingly when we detect we're on an M1 macos machine.
ifeq ("$(OS)-$(ARCH)", "Darwin-arm64")
CPATH := /opt/homebrew/include
LIBRARY_PATH := /opt/homebrew/lib
LDFLAGS := -L/opt/homebrew/opt/sqlite/lib
CPPFLAGS := -I/opt/homebrew/opt/sqlite/include
PKG_CONFIG_PATH=/opt/homebrew/opt/sqlite/lib/pkgconfig
else
CPATH := /usr/local/include
LIBRARY_PATH := /usr/local/lib
endif

CPPFLAGS += -DCLN_NEXT_VERSION="\"$(CLN_NEXT_VERSION)\"" -DPKGLIBEXECDIR="\"$(pkglibexecdir)\"" -DBINDIR="\"$(bindir)\"" -DPLUGINDIR="\"$(plugindir)\"" -DCCAN_TAL_NEVER_RETURN_NULL=1
CFLAGS = $(CPPFLAGS) $(CWARNFLAGS) $(CDEBUGFLAGS) $(COPTFLAGS) -I $(CCANDIR) $(EXTERNAL_INCLUDE_FLAGS) -I . -I$(CPATH) $(SQLITE3_CFLAGS) $(POSTGRES_INCLUDE) $(FEATURES) $(COVFLAGS) $(DEV_CFLAGS) -DSHACHAIN_BITS=48 -DJSMN_PARENT_LINKS $(PIE_CFLAGS) $(COMPAT_CFLAGS) $(CSANFLAGS)

# If CFLAGS is already set in the environment of make (to whatever value, it
# does not matter) then it would export it to subprocesses with the above value
# we set, including CWARNFLAGS which by default contains -Wall -Werror. This
# breaks at least libwally-core which tries to switch off some warnings with
# -Wno-whatever. So, tell make to not export our CFLAGS to subprocesses.
unexport CFLAGS

# We can get configurator to run a different compile cmd to cross-configure.
CONFIGURATOR_CC := $(CC)

LDFLAGS += $(PIE_LDFLAGS) $(CSANFLAGS) $(COPTFLAGS)

ifeq ($(STATIC),1)
# For MacOS, Jacob Rapoport <jacob@rumblemonkey.com> changed this to:
#  -L/usr/local/lib -lsqlite3 -lz -Wl,-lm -lpthread -ldl $(COVFLAGS)
# But that doesn't static link.
LDLIBS = -L$(CPATH) -Wl,-dn $(SQLITE3_LDLIBS) -Wl,-dy -lm -lpthread -ldl $(COVFLAGS)
else
LDLIBS = -L$(CPATH) -lm $(SQLITE3_LDLIBS) $(COVFLAGS)
endif

# If we have the postgres client library we need to link against it as well
ifeq ($(HAVE_POSTGRES),1)
LDLIBS += $(POSTGRES_LDLIBS)
endif

default: show-flags gen all-programs all-test-programs doc-all default-targets $(PYTHON_GENERATED)

ifneq ($(SUPPRESS_GENERATION),1)
FORCE = FORCE
FORCE:
endif

show-flags: config.vars
	@$(ECHO) "CC: $(CC) $(CFLAGS) -c -o"
	@$(ECHO) "LD: $(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) -o"

# We will re-generate, but we won't generate for the first time!
ccan/config.h config.vars &: configure ccan/tools/configurator/configurator.c
	@if [ ! -f config.vars ]; then echo 'File config.vars not found: you must run ./configure before running make.' >&2; exit 1; fi
	./configure --reconfigure

%.o: %.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)

# tools/update-mocks.sh does nasty recursive make, must not do this!
ifeq ($(SUPPRESS_GENERATION),1)
SHA256STAMP_CHANGED = false
SHA256STAMP = exit 1
else
# Git doesn't maintain timestamps, so we only regen if sources actually changed:
# We place the SHA inside some generated files so we can tell if they need updating.
# Usage: $(call SHA256STAMP_CHANGED)
SHA256STAMP_CHANGED = [ x"`sed -n 's/.*SHA256STAMP:\([a-f0-9]*\).*/\1/p' $@ 2>/dev/null`" != x"`cat $(sort $(filter-out FORCE,$^)) | $(SHA256SUM) | cut -c1-64`" ]
# Usage: $(call SHA256STAMP,commentprefix,commentpostfix)
SHA256STAMP = echo "$(1) SHA256STAMP:"`cat $(sort $(filter-out FORCE,$^)) | $(SHA256SUM) | cut -c1-64`"$(2)" >> $@
endif

# generate-wire.py --page [header|impl] hdrfilename wirename < csv > file
%_wiregen.h: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"wiregen $@",tools/generate-wire.py --page header $($@_args) $@ `basename $< .csv | sed 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_wiregen.c: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"wiregen $@",tools/generate-wire.py --page impl $($@_args) ${@:.c=.h} `basename $< .csv | sed 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_printgen.h: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"printgen $@",tools/generate-wire.py -s -P --page header $($@_args) $@ `basename $< .csv | sed 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_printgen.c: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"printgen $@",tools/generate-wire.py -s -P --page impl $($@_args) ${@:.c=.h} `basename $< .csv | sed 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

RUST_PROFILE ?= debug
ifneq ($(RUST_PROFILE),debug)
CARGO_OPTS := --profile=$(RUST_PROFILE) --quiet
else
CARGO_OPTS := --quiet
endif

include external/Makefile
include bitcoin/Makefile
include common/Makefile
include wire/Makefile
include db/Makefile
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
include contrib/msggen/Makefile
include devtools/Makefile
include tools/Makefile
include plugins/Makefile
include tests/plugins/Makefile

ifneq ($(FUZZING),0)
	include tests/fuzz/Makefile
endif
ifneq ($(RUST),0)
	include cln-rpc/Makefile
endif
include cln-grpc/Makefile

ifneq ($V,1)
MSGGEN_ARGS := -s
endif

$(MSGGEN_GENALL)&: contrib/msggen/msggen/schema.json
	@$(call VERBOSE, "msggen $@", PYTHONPATH=contrib/msggen $(PYTHON) contrib/msggen/msggen/__main__.py $(MSGGEN_ARGS) generate)

# The compiler assumes that the proto files are in the same
# directory structure as the generated files will be. Since we
# don't do that we need to path the files up.
GRPC_DIR = contrib/pyln-grpc-proto/pyln
GRPC_PATH = $(GRPC_DIR)/grpc

GRPC_GEN = \
	$(GRPC_PATH)/node_pb2.py \
	$(GRPC_PATH)/node_pb2_grpc.py \
	$(GRPC_PATH)/primitives_pb2.py

ALL_TEST_GEN += $(GRPC_GEN)

$(GRPC_GEN) &: cln-grpc/proto/node.proto cln-grpc/proto/primitives.proto
	$(PYTHON) -m grpc_tools.protoc -I cln-grpc/proto cln-grpc/proto/node.proto --python_out=$(GRPC_PATH)/ --grpc_python_out=$(GRPC_PATH)/ --experimental_allow_proto3_optional
	$(PYTHON) -m grpc_tools.protoc -I cln-grpc/proto cln-grpc/proto/primitives.proto --python_out=$(GRPC_PATH)/ --experimental_allow_proto3_optional
	find $(GRPC_DIR)/ -type f -name "*.py" -print0 | xargs -0 sed -i'.bak' -e 's/^import \(.*\)_pb2 as .*__pb2/from pyln.grpc import \1_pb2 as \1__pb2/g'
	find $(GRPC_DIR)/ -type f -name "*.py.bak" -print0 | xargs -0 rm -f

# We make pretty much everything depend on these.
ALL_GEN_HEADERS := $(filter %gen.h,$(ALL_C_HEADERS))
ALL_GEN_SOURCES := $(filter %gen.c,$(ALL_C_SOURCES))
ALL_NONGEN_HEADERS := $(filter-out %gen.h,$(ALL_C_HEADERS))
ALL_NONGEN_SOURCES := $(filter-out %gen.c,$(ALL_C_SOURCES))
ALL_NONGEN_SRCFILES := $(ALL_NONGEN_HEADERS) $(ALL_NONGEN_SOURCES)

# Programs to install in bindir and pkglibexecdir.
# TODO: $(EXEEXT) support for Windows?  Needs more coding for
# the individual Makefiles, however.
BIN_PROGRAMS = \
	       cli/lightning-cli \
	       lightningd/lightningd \
	       tools/lightning-hsmtool\
	       tools/reckless
PKGLIBEXEC_PROGRAMS = \
	       lightningd/lightning_channeld \
	       lightningd/lightning_closingd \
	       lightningd/lightning_connectd \
	       lightningd/lightning_dualopend \
	       lightningd/lightning_gossipd \
	       lightningd/lightning_hsmd \
	       lightningd/lightning_onchaind \
	       lightningd/lightning_openingd \
	       lightningd/lightning_websocketd

mkdocs.yml: $(MANPAGES:=.md)
	@$(call VERBOSE, "genidx $@", \
	  find doc -maxdepth 1 -name '*\.[0-9]\.md' | \
	  cut -b 5- | LC_ALL=C sort | \
	  sed 's/\(.*\)\.\(.*\).*\.md/- "\1": "\1.\2.md"/' | \
	  $(PYTHON) devtools/blockreplace.py mkdocs.yml manpages --language=yml --indent "          " \
	)



# Don't delete these intermediaries.
.PRECIOUS: $(ALL_GEN_HEADERS) $(ALL_GEN_SOURCES) $(PYTHON_GENERATED)

# Every single object file.
ALL_OBJS := $(ALL_C_SOURCES:.c=.o)

# We always regen wiregen and printgen files, since SHA256STAMP protects against
# spurious rebuilds.
$(filter %printgen.h %printgen.c %wiregen.h %wiregen.c, $(ALL_C_HEADERS) $(ALL_C_SOURCES)): $(FORCE)

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

# Allow for targeting specific tests by setting the PYTEST_TESTS environment variable.
ifeq ($(PYTEST_TESTS),)
PYTEST_TESTS = "tests/"
endif

check-units:

check: check-units installcheck pytest

pytest: $(ALL_PROGRAMS) $(DEFAULT_TARGETS) $(ALL_TEST_PROGRAMS) $(ALL_TEST_GEN)
ifeq ($(PYTEST),)
	@echo "py.test is required to run the integration tests, please install using 'pip3 install -r requirements.txt', and rerun 'configure'."
	exit 1
else
# Explicitly hand VALGRIND so you can override on make cmd line.
	PYTHONPATH=$(MY_CHECK_PYTHONPATH) TEST_DEBUG=1 VALGRIND=$(VALGRIND) $(PYTEST) $(PYTEST_TESTS) $(PYTEST_OPTS)
endif

check-fuzz: $(ALL_FUZZ_TARGETS)
ifneq ($(FUZZING),0)
	@tests/fuzz/check-fuzz.sh
else
	@echo "fuzzing is not enabled: first run './configure --enable-fuzzing'"
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

# We exclude test files, which need to do weird include tricks!
SRC_TO_CHECK := $(filter-out $(ALL_TEST_PROGRAMS:=.c), $(ALL_NONGEN_SOURCES))
check-src-includes: $(SRC_TO_CHECK:%=check-src-include-order/%)
check-hdr-includes: $(ALL_NONGEN_HEADERS:%=check-hdr-include-order/%)

# If you want to check a specific variant of quotes use:
#   make check-source-bolt BOLTVERSION=xxx
ifeq ($(BOLTVERSION),$(DEFAULT_BOLTVERSION))
CHECK_BOLT_PREFIX=
else
CHECK_BOLT_PREFIX=--prefix="BOLT-$(BOLTVERSION)"
endif

# Any mention of BOLT# must be followed by an exact quote, modulo whitespace.
bolt-check/%: % bolt-precheck tools/check-bolt
	@if [ -d .tmp.lightningrfc ]; then tools/check-bolt $(CHECK_BOLT_PREFIX) .tmp.lightningrfc $<; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi

LOCAL_BOLTDIR=.tmp.lightningrfc

bolt-precheck:
	@[ -d $(BOLTDIR) ] || exit 0; set -e; if [ -z "$(BOLTVERSION)" ]; then rm -rf $(LOCAL_BOLTDIR); ln -sf $(BOLTDIR) $(LOCAL_BOLTDIR); exit 0; fi; [ "$$(git -C $(LOCAL_BOLTDIR) rev-list --max-count=1 HEAD 2>/dev/null)" != "$(BOLTVERSION)" ] || exit 0; rm -rf $(LOCAL_BOLTDIR) && git clone -q $(BOLTDIR) $(LOCAL_BOLTDIR) && cd $(LOCAL_BOLTDIR) && git checkout -q $(BOLTVERSION)

check-source-bolt: $(ALL_NONGEN_SRCFILES:%=bolt-check/%)

check-whitespace/%: %
	@if grep -Hn '[ 	]$$' $<; then echo Extraneous whitespace found >&2; exit 1; fi

check-whitespace: check-whitespace/Makefile check-whitespace/tools/check-bolt.c $(ALL_NONGEN_SRCFILES:%=check-whitespace/%)

check-spelling:
	@tools/check-spelling.sh

PYSRC=$(shell git ls-files "*.py" | grep -v /text.py)

# Some tests in pyln will need to find lightningd to run, so have a PATH that
# allows it to find that
PYLN_PATH=$(shell pwd)/lightningd:$(PATH)
check-pyln-%: $(BIN_PROGRAMS) $(PKGLIBEXEC_PROGRAMS) $(PLUGINS)
	@(cd contrib/$(shell echo $@ | cut -b 7-) && PATH=$(PYLN_PATH) PYTHONPATH=$(MY_CHECK_PYTHONPATH) $(MAKE) check)

check-python: check-python-flake8 check-pytest-pyln-proto check-pyln-client check-pyln-testing

check-python-flake8:
	@# E501 line too long (N > 79 characters)
	@# E731 do not assign a lambda expression, use a def
	@# W503: line break before binary operator
	@# E741: ambiguous variable name
	@flake8 --ignore=E501,E731,E741,W503,F541,E275 --exclude $(shell echo ${PYTHON_GENERATED} | sed 's/ \+/,/g') ${PYSRC}

check-pytest-pyln-proto:
	PATH=$(PYLN_PATH) PYTHONPATH=$(MY_CHECK_PYTHONPATH) $(PYTEST) contrib/pyln-proto/tests/

check-includes: check-src-includes check-hdr-includes
	@tools/check-includes.sh

# cppcheck gets confused by list_for_each(head, i, list): thinks i is uninit.
.cppcheck-suppress: $(ALL_NONGEN_SRCFILES)
	@ls $(ALL_NONGEN_SRCFILES) | grep -vzE '^(ccan|contrib)/' | xargs grep -n '_for_each' | sed 's/\([^:]*:.*\):.*/uninitvar:\1/' > $@

check-cppcheck: .cppcheck-suppress
	@trap 'rm -f .cppcheck-suppress' 0; ls $(ALL_NONGEN_SRCFILES) | grep -vzE '^(ccan|contrib)/' | xargs cppcheck  ${CPPCHECK_OPTS}

check-shellcheck:
	@git ls-files -z -- "*.sh" | xargs -0 shellcheck -f gcc

check-setup_locale:
	@tools/check-setup_locale.sh

check-tmpctx:
	@if git grep -n 'tal_free[(]tmpctx)' | grep -Ev '^ccan/|/test/|^common/setup.c:|^common/utils.c:'; then echo "Don't free tmpctx!">&2; exit 1; fi

check-discouraged-functions:
	@if git grep -E "[^a-z_/](fgets|fputs|gets|scanf|sprintf)\(" -- "*.c" "*.h" ":(exclude)ccan/" ":(exclude)contrib/"; then exit 1; fi

# Don't access amount_msat and amount_sat members directly without a good reason
# since it risks overflow.
check-amount-access:
	@! (git grep -nE "(->|\.)(milli)?satoshis" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*" | grep -v '/* Raw:')
	@! git grep -nE "\\(struct amount_(m)?sat\\)" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*" | grep -vE "sizeof.struct amount_(m)?sat."

# For those without working cppcheck
check-source-no-cppcheck: check-makefile check-source-bolt check-whitespace check-spelling check-python check-includes check-shellcheck check-setup_locale check-tmpctx check-discouraged-functions check-amount-access

check-source: check-source-no-cppcheck check-cppcheck

full-check: check check-source

# Simple target to be used on CI systems to check that all the derived
# files were checked in and updated. It depends on the generated
# targets, and checks if any of the tracked files changed. If they did
# then one of the gen-targets caused this change, meaning either the
# gen-target is not reproducible or the files were forgotten.
#
# Do not run on your development tree since it will complain if you
# have a dirty tree.
CHECK_GEN_ALL = \
	$(CLN_GRPC_GENALL) \
	$(CLN_RPC_GENALL) \
	$(MANPAGES) \
	$(WALLET_DB_QUERIES) \
	$(PYTHON_GENERATED) \
	$(ALL_GEN_HEADERS) \
	$(ALL_GEN_SOURCES) \
	$(MSGGEN_GEN_ALL) \
	wallet/statements_gettextgen.po \
	doc/index.rst

gen:  $(CHECK_GEN_ALL)

check-gen-updated:  $(CHECK_GEN_ALL)
	@echo "Checking for generated files being changed by make"
	git diff --exit-code HEAD

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
TAGS:
	$(RM) TAGS; find * -name test -type d -prune -o \( -name '*.[ch]' -o -name '*.py' \) -print0 | xargs -0 etags --append

tags:
	$(RM) tags; find * -name test -type d -prune -o \( -name '*.[ch]' -o -name '*.py' \) -print0 | xargs -0 ctags --append

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

ALL_PROGRAMS += ccan/ccan/cdump/tools/cdump-enumstr
# Can't add to ALL_OBJS, as that makes a circular dep.
ccan/ccan/cdump/tools/cdump-enumstr.o: $(CCAN_HEADERS) Makefile

# Without a working git, you can't generate this file, so assume if it exists
# it is ok (fixes "sudo make install").
ifeq ($(VERSION),)
version_gen.h:
	echo "ERROR: git is required for generating version information" >&2
	exit 1
else
version_gen.h: $(FORCE)
	@(echo "#define VERSION \"$(VERSION)\"" && echo "#define BUILD_FEATURES \"$(FEATURES)\"") > $@.new
	@if cmp $@.new $@ >/dev/null 2>&1; then rm -f $@.new; else mv $@.new $@; $(ECHO) Version updated; fi
endif

# That forces this rule to be run every time, too.
header_versions_gen.h: tools/headerversions $(FORCE)
	@tools/headerversions $@

# We make a static library, this way linker can discard unused parts.
libccan.a: $(CCAN_OBJS)
	@$(call VERBOSE, "ar $@", $(AR) r $@ $(CCAN_OBJS))

# All binaries require the external libs, ccan and system library versions.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS): $(EXTERNAL_LIBS) libccan.a

# Each test program depends on its own object.
$(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS): %: %.o

# Without this rule, the (built-in) link line contains
# external/libwallycore.a directly, which causes a symbol clash (it
# uses some ccan modules internally).  We want to rely on -lwallycore etc.
# (as per EXTERNAL_LDLIBS) so we filter them out here.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS):
	@$(call VERBOSE, "ld $@", $(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) libccan.a $($(@)_LDLIBS) -o $@)

# We special case the fuzzing target binaries, as they need to link against libfuzzer,
# which brings its own main().
FUZZ_LDFLAGS = -fsanitize=fuzzer
$(ALL_FUZZ_TARGETS):
	@$(call VERBOSE, "ld $@", $(LINK.o) $(filter-out %.a,$^) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) libccan.a $(FUZZ_LDFLAGS) -o $@)


# Everything depends on the CCAN headers, and Makefile
$(CCAN_OBJS) $(CDUMP_OBJS): $(CCAN_HEADERS) Makefile ccan_compat.h

# Except for CCAN, we treat everything else as dependent on external/ bitcoin/ common/ wire/ and all generated headers, and Makefile
$(ALL_OBJS): $(BITCOIN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS) $(WIRE_HEADERS) $(ALL_GEN_HEADERS) $(EXTERNAL_HEADERS) Makefile

# Test files can literally #include generated C files.
$(ALL_TEST_PROGRAMS:=.o): $(ALL_GEN_SOURCES)

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
all-test-programs: $(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS)
default-targets: $(DEFAULT_TARGETS)

distclean: clean
	$(RM) ccan/config.h config.vars

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'
	$(RM) $(PYTHON_GENERATED)

# We used to have gen_ files, now we have _gen files.
obsclean:
	$(RM) gen_*.h */gen_*.[ch] */*/gen_*.[ch]

clean: obsclean
	$(RM) libccan.a $(CCAN_OBJS) $(CDUMP_OBJS) $(ALL_OBJS)
	$(RM) $(ALL_GEN_HEADERS) $(ALL_GEN_SOURCES)
	$(RM) $(ALL_PROGRAMS)
	$(RM) $(ALL_TEST_PROGRAMS)
	$(RM) $(ALL_FUZZ_TARGETS)
	$(RM) $(MSGGEN_GEN_ALL)
	$(RM) ccan/tools/configurator/configurator
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr.o
	find . -name '*gcda' -delete
	find . -name '*gcno' -delete
	find . -name '*.nccout' -delete
	if [ "${RUST}" -eq "1" ]; then cargo clean; fi


PYLNS=client proto testing
# See doc/contribute-to-core-lightning/contributor-workflow.md
update-versions: update-pyln-versions update-clnrest-version update-wss-proxy-version update-poetry-lock update-dot-version

update-pyln-versions: $(PYLNS:%=update-pyln-version-%)

update-pyln-version-%:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	cd contrib/pyln-$* && $(MAKE) upgrade-version

pyln-release:  $(PYLNS:%=pyln-release-%)

pyln-release-%:
	cd contrib/pyln-$* && $(MAKE) prod-release

update-clnrest-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	cd plugins/clnrest && $(MAKE) upgrade-version

update-wss-proxy-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	cd plugins/wss-proxy && $(MAKE) upgrade-version

update-poetry-lock:
	poetry update clnrest wss-proxy pyln-client pyln-proto pyln-testing update-reckless-version

update-reckless-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	@sed -i "s/__VERSION__ = '\([.-z]*\)'/__VERSION__ = '$(NEW_VERSION)'/" tools/reckless

update-dot-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	echo $(NEW_VERSION) > .version

update-mocks: $(ALL_TEST_PROGRAMS:%=update-mocks/%.c)

$(ALL_TEST_PROGRAMS:%=update-mocks/%.c): $(ALL_GEN_HEADERS) $(EXTERNAL_LIBS) libccan.a ccan/ccan/cdump/tools/cdump-enumstr config.vars

update-mocks/%: % $(ALL_GEN_HEADERS) $(ALL_GEN_SOURCES)
	@MAKE=$(MAKE) tools/update-mocks.sh "$*" $(SUPPRESS_OUTPUT)

unittest/%: % bolt-precheck
	BOLTDIR=$(LOCAL_BOLTDIR) $(VG) $(VG_TEST_ARGS) $* > /dev/null

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

# $(PLUGINS) is defined in plugins/Makefile.

install-program: installdirs $(BIN_PROGRAMS) $(PKGLIBEXEC_PROGRAMS) $(PLUGINS) $(PY_PLUGINS)
	@$(NORMAL_INSTALL)
	$(INSTALL_PROGRAM) $(BIN_PROGRAMS) $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) $(PKGLIBEXEC_PROGRAMS) $(DESTDIR)$(pkglibexecdir)
	[ -z "$(PLUGINS)" ] || $(INSTALL_PROGRAM) $(PLUGINS) $(DESTDIR)$(plugindir)
	for PY in $(PY_PLUGINS); do DIR=`dirname $$PY`; DST=$(DESTDIR)$(plugindir)/`basename $$DIR`; if [ -d $$DST ]; then rm -rf $$DST; fi; $(INSTALL_PROGRAM) -d $$DIR; cp -a $$DIR $$DST ; done

MAN1PAGES = $(filter %.1,$(MANPAGES))
MAN5PAGES = $(filter %.5,$(MANPAGES))
MAN7PAGES = $(filter %.7,$(MANPAGES))
MAN8PAGES = $(filter %.8,$(MANPAGES))
DOC_DATA = README.md LICENSE

install-data: installdirs $(MAN1PAGES) $(MAN5PAGES) $(MAN7PAGES) $(MAN8PAGES) $(DOC_DATA)
	@$(NORMAL_INSTALL)
	$(INSTALL_DATA) $(MAN1PAGES) $(DESTDIR)$(man1dir)
	$(INSTALL_DATA) $(MAN5PAGES) $(DESTDIR)$(man5dir)
	$(INSTALL_DATA) $(MAN7PAGES) $(DESTDIR)$(man7dir)
	$(INSTALL_DATA) $(MAN8PAGES) $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) $(DOC_DATA) $(DESTDIR)$(docdir)

install: install-program install-data

# Non-artifacts that are needed for testing. These are added to the
# testpack.tar, used to transfer things between builder and tester
# phase. If you get a missing file/executable while testing on CI it
# is likely missing from this variable.
TESTBINS = \
	$(CLN_PLUGIN_EXAMPLES) \
	tests/plugins/test_libplugin \
	tests/plugins/test_selfdisable_after_getmanifest \
	tools/hsmtool

# The testpack is used in CI to transfer built artefacts between the
# build and the test phase. This is necessary because the fixtures in
# `tests/` explicitly use the binaries built in the current directory
# rather than using `$PATH`, as that may pick up some other installed
# version of `lightningd` leading to bogus results. We bundle up all
# built artefacts here, and will unpack them on the tester (overlaying
# on top of the checked out repo as if we had just built it in place).
testpack.tar.bz2: $(BIN_PROGRAMS) $(PKGLIBEXEC_PROGRAMS) $(PLUGINS) $(PY_PLUGINS) $(MAN1PAGES) $(MAN5PAGES) $(MAN7PAGES) $(MAN8PAGES) $(DOC_DATA) config.vars $(TESTBINS) $(DEVTOOLS)
	tar -caf $@ $^

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
	@for f in $(PY_PLUGINS); do \
	  $(ECHO) rm -rf $(DESTDIR)$(plugindir)/$$(basename $$(dirname $$f)); \
	  rm -rf $(DESTDIR)$(plugindir)/$$(basename $$(dirname $$f)); \
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
ifneq ($(VERSION),)
bin-tarball: clightning-$(VERSION)-$(DISTRO).tar.xz
clightning-$(VERSION)-$(DISTRO).tar.xz: DESTDIR=$(shell pwd)/
clightning-$(VERSION)-$(DISTRO).tar.xz: prefix=opt/clightning
clightning-$(VERSION)-$(DISTRO).tar.xz: install
	trap "rm -rf opt" 0; tar cvfa $@ opt/
endif

ccan-breakpoint.o: $(CCANDIR)/ccan/breakpoint/breakpoint.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-base64.o: $(CCANDIR)/ccan/base64/base64.c
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
ccan-strset.o: $(CCANDIR)/ccan/strset/strset.c
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
ccan-closefrom.o: $(CCANDIR)/ccan/closefrom/closefrom.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-rune-rune.o: $(CCANDIR)/ccan/rune/rune.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
ccan-rune-coding.o: $(CCANDIR)/ccan/rune/coding.c
	@$(call VERBOSE, "cc $<", $(CC) $(CFLAGS) -c -o $@ $<)
