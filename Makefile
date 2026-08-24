#! /usr/bin/make

# Prefer VERSION from environment if provided (e.g., from GitHub Actions)
# Extract version from git, or if we're from a zipfile, use dirname
VERSION ?= $(shell git describe --tags --always --dirty=-modded --abbrev=7 2>/dev/null || \
	pwd | $(SED) -n 's|.*/c\{0,1\}lightning-v\{0,1\}\([0-9a-f.rc\-]*\)$$|v\1|gp')
$(info Building version $(VERSION))

# Next release.
CLN_NEXT_VERSION := v26.09

# Previous release (for downgrade testing)
CLN_PREV_VERSION := v26.06

# --quiet / -s means quiet, dammit!
ifeq ($(findstring s,$(word 1, $(MAKEFLAGS))),s)
ECHO := :
SUPPRESS_OUTPUT := > /dev/null
else
ECHO := echo
SUPPRESS_OUTPUT :=
endif

CARGO := cargo
DISTRO=$(shell lsb_release -is 2>/dev/null || echo unknown)-$(shell lsb_release -rs 2>/dev/null || echo unknown)
OS=$(shell uname -s)
ARCH=$(shell uname -m)
# Changing this could break installs!
PKGNAME = c-lightning

# We use our own internal ccan copy.
CCANDIR := ccan

# Where we keep the BOLT RFCs
BOLTDIR := ../bolts/
DEFAULT_BOLTVERSION := 4b539711d4726f274482051150bc6612e370b4e2
# Can be overridden on cmdline.
BOLTVERSION := $(DEFAULT_BOLTVERSION)

-include config.vars

# Save flags inherited from environment (or config.vars) before we start munging them
CFLAGS_FROM_ENV := $(CFLAGS)
CFLAGS =
CPPFLAGS_FROM_ENV := $(CPPFLAGS)
CPPFLAGS =
LDFLAGS_FROM_ENV := $(LDFLAGS)
LDFLAGS =

# Look up the host machine tuple if not specified
ifndef HOST
HOST := $(shell $(CC) $(CFLAGS_FROM_ENV) -dumpmachine)
endif

# Set a default build directory if not specified
ifndef BUILDDIR
BUILDDIR := build/$(HOST)
endif

# Use Homebrew LLVM toolchain for fuzzing support on macOS
ifeq ($(OS),Darwin)
export PATH := /opt/homebrew/opt/llvm/bin:$(PATH)
export DYLD_LIBRARY_PATH := /opt/homebrew/opt/llvm/lib:$(DYLD_LIBRARY_PATH)
endif

# Define EXTERNAL_LDLIBS for linking external libraries
EXTERNAL_LDLIBS=$(SODIUM_LDLIBS) $(SQLITE3_LDLIBS) $(POSTGRES_LDLIBS)

SORT=LC_ALL=C sort


ifeq ($V,1)
VERBOSE = $(ECHO) '$(subst ','\'',$(2))'; $(2)
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

# This is where we add new features as bitcoin adds them.
FEATURES :=

CCAN_OBJS :=					\
	$(addprefix $(BUILDDIR)/$(CCANDIR)/ccan/, \
	asort/asort.o				\
	base64/base64.o				\
	bitmap/bitmap.o				\
	bitops/bitops.o				\
	breakpoint/breakpoint.o			\
	cdump/cdump.o				\
	closefrom/closefrom.o			\
	crc32c/crc32c.o				\
	crypto/hkdf_sha256/hkdf_sha256.o	\
	crypto/hmac_sha256/hmac_sha256.o	\
	crypto/ripemd160/ripemd160.o		\
	crypto/sha256/sha256.o			\
	crypto/shachain/shachain.o		\
	crypto/siphash24/siphash24.o		\
	err/err.o				\
	fdpass/fdpass.o				\
	htable/htable.o				\
	ilog/ilog.o				\
	intmap/intmap.o				\
	io/fdpass/fdpass.o			\
	io/io.o					\
	io/poll.o				\
	isaac/isaac.o				\
	isaac/isaac64.o				\
	json_escape/json_escape.o		\
	json_out/json_out.o			\
	list/list.o				\
	mem/mem.o				\
	membuf/membuf.o				\
	noerr/noerr.o				\
	opt/helpers.o				\
	opt/opt.o				\
	opt/parse.o				\
	opt/usage.o				\
	pipecmd/pipecmd.o			\
	ptr_valid/ptr_valid.o			\
	rbuf/rbuf.o				\
	read_write_all/read_write_all.o		\
	rune/coding.o				\
	rune/rune.o				\
	str/base32/base32.o			\
	str/hex/hex.o				\
	str/str.o				\
	strmap/strmap.o				\
	strset/strset.o				\
	take/take.o				\
	tal/grab_file/grab_file.o		\
	tal/link/link.o				\
	tal/path/path.o				\
	tal/str/str.o				\
	tal/tal.o				\
	time/time.o				\
	timer/timer.o				\
	utf8/utf8.o				\
	)

CCAN_HEADERS :=					\
	$(CCANDIR)/config.h			\
	$(addprefix $(CCANDIR)/ccan/,		\
	alignof/alignof.h			\
	array_size/array_size.h			\
	asort/asort.h				\
	base64/base64.h				\
	bitmap/bitmap.h				\
	bitops/bitops.h				\
	breakpoint/breakpoint.h			\
	build_assert/build_assert.h		\
	cast/cast.h				\
	cdump/cdump.h				\
	check_type/check_type.h			\
	closefrom/closefrom.h			\
	compiler/compiler.h			\
	container_of/container_of.h		\
	cppmagic/cppmagic.h			\
	crc32c/crc32c.h				\
	crypto/hkdf_sha256/hkdf_sha256.h 	\
	crypto/hmac_sha256/hmac_sha256.h	\
	crypto/ripemd160/ripemd160.h		\
	crypto/sha256/sha256.h			\
	crypto/shachain/shachain.h		\
	crypto/siphash24/siphash24.h		\
	endian/endian.h				\
	err/err.h				\
	fdpass/fdpass.h				\
	graphql/graphql.h			\
	htable/htable.h				\
	htable/htable_type.h			\
	ilog/ilog.h				\
	intmap/intmap.h				\
	io/backend.h				\
	io/fdpass/fdpass.h			\
	io/io.h					\
	io/io_plan.h				\
	isaac/isaac.h				\
	isaac/isaac64.h				\
	json_escape/json_escape.h		\
	json_out/json_out.h			\
	likely/likely.h				\
	list/list.h				\
	lqueue/lqueue.h				\
	mem/mem.h				\
	membuf/membuf.h				\
	noerr/noerr.h				\
	opt/opt.h				\
	opt/private.h				\
	order/order.h				\
	pipecmd/pipecmd.h			\
	ptr_valid/ptr_valid.h			\
	ptrint/ptrint.h				\
	rbuf/rbuf.h				\
	read_write_all/read_write_all.h		\
	rune/internal.h				\
	rune/rune.h				\
	short_types/short_types.h		\
	str/base32/base32.h			\
	str/hex/hex.h				\
	str/str.h				\
	str/str_debug.h				\
	strmap/strmap.h				\
	strset/strset.h				\
	structeq/structeq.h			\
	take/take.h				\
	tal/grab_file/grab_file.h		\
	tal/link/link.h				\
	tal/path/path.h				\
	tal/str/str.h				\
	tal/tal.h				\
	tcon/tcon.h				\
	time/time.h				\
	timer/timer.h				\
	typesafe_cb/typesafe_cb.h		\
	utf8/utf8.h				\
	)

BOLT_GEN := tools/generate-wire.py
WIRE_GEN := $(BOLT_GEN)

# If you use wiregen, you're dependent on the tool and its templates
WIRE_GEN_DEPS := $(WIRE_GEN) $(wildcard tools/gen/*_template)

# These are filled by individual Makefiles
ALL_PROGRAMS :=
ALL_BUILD_PROGRAMS :=
ALL_TEST_PROGRAMS :=
ALL_TEST_GEN :=
ALL_FUZZ_TARGETS :=
ALL_C_SOURCES :=
ALL_C_HEADERS :=
# Extra (non C) targets that should be built by default.
DEFAULT_TARGETS :=

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

# M1 macos machines with homebrew will install the native libraries in
# /opt/homebrew instead of /usr/local, most likely because they
# emulate x86_64 compatibility via Rosetta, and wanting to keep the
# libraries separate. This however means we also need to switch out
# the paths accordingly when we detect we're on an M1 macos machine.
ifeq ("$(OS)-$(ARCH)", "Darwin-arm64")
CPATH := /opt/homebrew/include
LIBRARY_PATH := /opt/homebrew/lib
else
CPATH := /usr/local/include
LIBRARY_PATH := /usr/local/lib
endif

# Detect OpenSSL and SQLite paths dynamically using brew --prefix
ifeq ("$(OS)", "Darwin")
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "")
SQLITE_PREFIX := $(shell brew --prefix sqlite 2>/dev/null || echo "")
ifneq ("$(OPENSSL_PREFIX)", "")
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
endif
ifneq ("$(SQLITE_PREFIX)", "")
LDFLAGS += -L$(SQLITE_PREFIX)/lib
CPPFLAGS += -I$(SQLITE_PREFIX)/include
PKG_CONFIG_PATH := $(SQLITE_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
endif
endif

# Put the environment-inherited flags *last* so the user has the final say.
CPPFLAGS += -DCLN_NEXT_VERSION="\"$(CLN_NEXT_VERSION)\"" -DPKGLIBEXECDIR="\"$(pkglibexecdir)\"" -DBINDIR="\"$(bindir)\"" -DPLUGINDIR="\"$(plugindir)\"" -DCCAN_TAL_NEVER_RETURN_NULL=1 -I$(CCANDIR) $(EXTERNAL_INCLUDE_FLAGS) -I. -I$(BUILDDIR) -I$(CPATH) $(POSTGRES_INCLUDE) -DSHACHAIN_BITS=48 -DJSMN_PARENT_LINKS $(COMPAT_CFLAGS) $(CPPFLAGS_FROM_ENV)
CFLAGS = $(CWARNFLAGS) $(CDEBUGFLAGS) $(COPTFLAGS) $(SQLITE3_CFLAGS) $(SODIUM_CFLAGS) $(FEATURES) $(COVFLAGS) $(DEV_CFLAGS) $(PIE_CFLAGS) $(CSANFLAGS) $(CFLAGS_FROM_ENV)
LDFLAGS += $(PIE_LDFLAGS) $(LDFLAGS_FROM_ENV)

# If CFLAGS is already set in the environment of make (to whatever value, it
# does not matter) then it would export it to subprocesses with the above value
# we set, including CWARNFLAGS which by default contains -Wall -Werror. This
# breaks at least libwally-core which tries to switch off some warnings with
# -Wno-whatever. So, tell make to not export our CFLAGS to subprocesses.
unexport CFLAGS

# We can get configurator to run a different compile cmd to cross-configure.
CONFIGURATOR_CC := $(CC)

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
	@$(ECHO) "CC: $(COMPILE.c) -o"
	@$(ECHO) "LD: $(LINK.c) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) -o"

# We will re-generate, but we won't generate for the first time!
ccan/config.h config.vars &: configure ccan/tools/configurator/configurator.c
	@if [ ! -f config.vars ]; then echo 'File config.vars not found: you must run ./configure before running make.' >&2; exit 1; fi
	./configure --reconfigure

%/:
	@$(MKDIR_P) $(@D)

# Update all archive members using a single ar invocation. This un-breaks parallel Make.
(%) : % ;
%.a :
	@$(call VERBOSE,"ar $@",$(AR) r $@ $?)

# tools/update-mocks.sh does nasty recursive make, must not do this!
ifeq ($(SUPPRESS_GENERATION),1)
SHA256STAMP_CHANGED = false
SHA256STAMP = exit 1
else
# Git doesn't maintain timestamps, so we only regen if sources actually changed:
# We place the SHA inside some generated files so we can tell if they need updating.
# Usage: $(call SHA256STAMP_CHANGED)
SHA256STAMP_CHANGED = [ x"`$(SED) -n 's/.*SHA256STAMP:\([a-f0-9]*\).*/\1/p' $@ 2>/dev/null`" != x"`cat $(sort $(filter-out FORCE,$^)) | $(SHA256SUM) | cut -c1-64`" ]
# Usage: $(call SHA256STAMP,commentprefix,commentpostfix)
SHA256STAMP = echo "$(1) SHA256STAMP:"`cat $(sort $(filter-out FORCE,$^)) | $(SHA256SUM) | cut -c1-64`"$(2)" >> $@
endif

CDUMP_ENUMSTR := $(BUILDDIR)/ccan/ccan/cdump/tools/cdump-enumstr

# generate-wire.py --page [header|impl] hdrfilename wirename < csv > file
%_wiregen.h: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"wiregen $@",tools/generate-wire.py --page header $($@_args) $@ `basename $< .csv | $(SED) 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_wiregen.c: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"wiregen $@",tools/generate-wire.py --page impl $($@_args) ${@:.c=.h} `basename $< .csv | $(SED) 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_printgen.h: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"printgen $@",tools/generate-wire.py -s -P --page header $($@_args) $@ `basename $< .csv | $(SED) 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

%_printgen.c: %_wire.csv $(WIRE_GEN_DEPS)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"printgen $@",tools/generate-wire.py -s -P --page impl $($@_args) ${@:.c=.h} `basename $< .csv | $(SED) 's/_exp_/_/'` < $< > $@ && $(call SHA256STAMP,//,)); \
	fi

RUST_PROFILE ?= debug

# Cargo places cross compiled packages in a different directory, using the target triple
ifeq ($(TARGET),)
RUST_TARGET_DIR = target/$(RUST_PROFILE)
else
RUST_TARGET_DIR = target/$(TARGET)/$(RUST_PROFILE)
endif

ifneq ($(RUST_PROFILE),debug)
CARGO_OPTS := --profile=$(RUST_PROFILE) --locked --quiet
else
CARGO_OPTS := --quiet
endif

include external/Makefile
include bitcoin/Makefile
include wire/Makefile
include common/Makefile
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
ifneq ($(RUST),0)
include cln-rpc/Makefile
include cln-grpc/Makefile
endif
include plugins/Makefile
include tests/plugins/Makefile

# Only include fuzz tests if OpenSSL >= 3.0, will be disabled on ubuntu focal
OPENSSL_VERSION := $(shell openssl version | $(SED) -n 's/OpenSSL \([0-9]\+\)\..*/\1/p')
ifneq ($(shell test $(OPENSSL_VERSION) -ge 3 && echo yes),)
include tests/fuzz/Makefile
endif

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

CLN_GRPC_GENALL += $(GRPC_GEN)
ALL_TEST_GEN += $(GRPC_GEN)

$(GRPC_GEN) &: cln-grpc/proto/node.proto cln-grpc/proto/primitives.proto
	$(PYTHON) -m grpc_tools.protoc -I cln-grpc/proto cln-grpc/proto/node.proto --python_out=$(GRPC_PATH)/ --grpc_python_out=$(GRPC_PATH)/ --experimental_allow_proto3_optional
	$(PYTHON) -m grpc_tools.protoc -I cln-grpc/proto cln-grpc/proto/primitives.proto --python_out=$(GRPC_PATH)/ --experimental_allow_proto3_optional
	find $(GRPC_DIR)/ -type f -name "*.py" -print0 | xargs -0 $(SED) -i'.bak' -e 's/^import \(.*\)_pb2 as .*__pb2/from pyln.grpc import \1_pb2 as \1__pb2/g'
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
	$(addprefix $(BUILDDIR)/, \
	       cli/lightning-cli \
	       lightningd/lightningd \
	       tools/lightning-hsmtool\
	) \
	       tools/reckless
PKGLIBEXEC_PROGRAMS = \
	$(addprefix $(BUILDDIR)/, \
	       lightningd/lightning_channeld \
	       lightningd/lightning_closingd \
	       lightningd/lightning_connectd \
	       lightningd/lightning_dualopend \
	       lightningd/lightning_gossipd \
	       lightningd/lightning_gossip_compactd \
	       lightningd/lightning_hsmd \
	       lightningd/lightning_onchaind \
	       lightningd/lightning_openingd \
	       lightningd/lightning_websocketd \
	)

mkdocs.yml: $(MANPAGES:=.md)
	@$(call VERBOSE, "genidx $@", \
	  find doc -maxdepth 1 -name '*\.[0-9]\.md' | \
	  cut -b 5- | LC_ALL=C sort | \
	  $(SED) 's/\(.*\)\.\(.*\).*\.md/- "\1": "\1.\2.md"/' | \
	  $(PYTHON) devtools/blockreplace.py mkdocs.yml manpages --language=yml --indent "          " \
	)


# Every single object file.
ALL_OBJS := $(ALL_C_SOURCES:%.c=$(BUILDDIR)/%.o)

WIREGEN_FILES := $(filter %printgen.h %printgen.c %wiregen.h %wiregen.c, $(ALL_C_HEADERS) $(ALL_C_SOURCES))

# Always make wiregen files before any object file
$(ALL_OBJS): $(WIREGEN_FILES)

# We always regen wiregen and printgen files, since SHA256STAMP protects against
# spurious rebuilds.
$(WIREGEN_FILES): $(FORCE)

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
	@echo "pytest is required to run the integration tests, please install using 'uv sync --all-extras --all-groups', and rerun 'configure'."
	exit 1
else
# Explicitly hand VALGRIND so you can override on make cmd line.
	PYTHONPATH=$(MY_CHECK_PYTHONPATH) TEST_DEBUG=1 TEST_LOG_IGNORE_ERRORS=1 VALGRIND=$(VALGRIND) uv run $(PYTEST) $(PYTEST_TESTS) $(PYTEST_OPTS)
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

print-src-to-check:
	@echo $(SRC_TO_CHECK)
print-hdr-to-check:
	@echo $(ALL_NONGEN_HEADERS)

# If you want to check a specific variant of quotes use:
#   make check-source-bolt BOLTVERSION=xxx
ifeq ($(BOLTVERSION),$(DEFAULT_BOLTVERSION))
CHECK_BOLT_COMMIT=
else
CHECK_BOLT_COMMIT=--include-commit=$(BOLTVERSION)
endif

CHECK_QUOTES := devtools/check_quotes.py

BOLT_COVERAGE_FLAGS=$(if $(COVERAGE_FILE),--coverage=$(COVERAGE_FILE),)

# Any mention of BOLT# must be followed by an exact quote, modulo whitespace.
bolt-check/%: % bolt-precheck
	@if [ -d .tmp.lightningrfc ]; then uv run $(CHECK_QUOTES) -k $(CHECK_BOLT_COMMIT) --comment-start "/* " --comment-continue "*" --comment-end "*/" --boltdir .tmp.lightningrfc $(BOLT_COVERAGE_FLAGS) $<; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi

bolt-check-py/%: % bolt-precheck
	@if [ -d .tmp.lightningrfc ]; then uv run $(CHECK_QUOTES) -k $(CHECK_BOLT_COMMIT) --boltdir .tmp.lightningrfc $(BOLT_COVERAGE_FLAGS) $<; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi

bolt-check-rs/%: % bolt-precheck
	@if [ -d .tmp.lightningrfc ]; then uv run $(CHECK_QUOTES) -k $(CHECK_BOLT_COMMIT) --comment-start "// " --comment-continue "//" --boltdir .tmp.lightningrfc $(BOLT_COVERAGE_FLAGS) $<; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi

LOCAL_BOLTDIR=.tmp.lightningrfc

bolt-precheck:
	@[ -d $(BOLTDIR) ] || exit 0; set -e; if [ -z "$(BOLTVERSION)" ]; then rm -rf $(LOCAL_BOLTDIR); ln -sf $(BOLTDIR) $(LOCAL_BOLTDIR); exit 0; fi; [ "$$(git -C $(LOCAL_BOLTDIR) rev-list --max-count=1 HEAD 2>/dev/null)" != "$(BOLTVERSION)" ] || exit 0; rm -rf $(LOCAL_BOLTDIR) && git clone -q $(BOLTDIR) $(LOCAL_BOLTDIR) && cd $(LOCAL_BOLTDIR) && git checkout -q $(BOLTVERSION)

PYSRC=$(shell git ls-files "*.py" | grep -v /text.py)
RUSTSRC=$(shell git ls-files "*.rs")

check-source-bolt: $(ALL_NONGEN_SRCFILES:%=bolt-check/%) $(PYSRC:%=bolt-check-py/%) $(RUSTSRC:%=bolt-check-rs/%)

check-requirements-coverage: bolt-precheck
	@if [ ! -d .tmp.lightningrfc ]; then echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; exit 1; fi
	@f=/tmp/cln-bolt-coverage.$$$$; \
	 rm -f $$f; \
	 $(MAKE) check-source-bolt COVERAGE_FILE=$$f && \
	 uv run devtools/bolt-coverage.py --coverage $$f --boltdir .tmp.lightningrfc; \
	 rc=$$?; rm -f $$f; exit $$rc

check-whitespace/%: %
	@if grep -Hn '[ 	]$$' $<; then echo Extraneous whitespace found >&2; exit 1; fi

check-whitespace: check-whitespace/Makefile $(ALL_NONGEN_SRCFILES:%=check-whitespace/%)

check-spelling:
	@tools/check-spelling.sh

# Some tests in pyln will need to find lightningd to run, so have a PATH that
# allows it to find that
PYLN_PATH=$(shell pwd)/lightningd:$(PATH)
check-pyln-%: $(BIN_PROGRAMS) $(PKGLIBEXEC_PROGRAMS) $(PLUGINS)
	@(cd contrib/$(shell echo $@ | cut -b 7-) && PATH=$(PYLN_PATH) PYTHONPATH=$(MY_CHECK_PYTHONPATH) uv run $(MAKE) check)

check-python: check-python-flake8 check-pytest-pyln-proto check-pyln-client check-pyln-testing

check-python-flake8:
	@# E501 line too long (N > 79 characters)
	@# E731 do not assign a lambda expression, use a def
	@# W503: line break before binary operator
	@# E741: ambiguous variable name
	@uv run flake8 --ignore=E501,E731,E741,W503,F541,E275 --exclude $(shell echo ${PYTHON_GENERATED} | $(SED) 's/ \+/,/g') ${PYSRC}

check-pytest-pyln-proto:
	PATH=$(PYLN_PATH) PYTHONPATH=$(MY_CHECK_PYTHONPATH) uv run $(PYTEST) contrib/pyln-proto/tests/

check-includes: check-src-includes check-hdr-includes
	@tools/check-includes.sh

check-shellcheck:
	@git ls-files -z -- "*.sh" | xargs -0 shellcheck -f gcc

check-setup_locale:
	@tools/check-setup_locale.sh

check-tmpctx:
	@if git grep -n 'tal_free[(]tmpctx)' | grep -Ev '^ccan/|/test/|^common/setup.c:|^common/utils.c:'; then echo "Don't free tmpctx!">&2; exit 1; fi

check-discouraged-functions:
	@if git grep -nE "[^a-z_/](fgets|fputs|gets|scanf|sprintf|randombytes_buf|time_now)\(" -- "*.c" "*.h" ":(exclude)ccan/" ":(exclude)contrib/" | grep -Fv '/* discouraged:'; then exit 1; fi

check-bad-sprintf:
	@if git grep -n "%[*]\.s"; then exit 1; fi

# Don't access amount_msat and amount_sat members directly without a good reason
# since it risks overflow.
check-amount-access:
	@! (git grep -nE "(->|\.)(milli)?satoshis" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*" ":(exclude)tests/fuzz/*" | grep -v '/* Raw:')
	@! git grep -nE "\\(struct amount_(m)?sat\\)" -- "*.c" "*.h" ":(exclude)common/amount.*" ":(exclude)*/test/*" ":(exclude)tests/fuzz/*" | grep -vE "sizeof.struct amount_(m)?sat."

# Examples must be generated with this tree's binaries to use plugins and tools
DOC_EXAMPLES_PATH = $(CURDIR)/lightningd:$(CURDIR)/cli:$(CURDIR)/tools:$(PATH)

repeat-doc-examples:
	@for i in $$(seq 1 $(n)); do \
		PORT_OFFSET=$$((i * 100)); \
		BASE_PORTNUM=$$((30000 + PORT_OFFSET)); \
		echo "----------------------------------" >> tests/autogenerate-examples-repeat.log; \
		echo "Iteration $$i on Base Port $$BASE_PORTNUM" >> tests/autogenerate-examples-repeat.log; \
		echo "----------------------------------" >> tests/autogenerate-examples-repeat.log; \
		PATH="$(DOC_EXAMPLES_PATH)" TEST_DEBUG=1 VALGRIND=0 GENERATE_EXAMPLES=1 CLN_NEXT_VERSION=$(CLN_NEXT_VERSION) BASE_PORTNUM=$$BASE_PORTNUM pytest -vvv --timeout=1200 tests/autogenerate-rpc-examples.py; \
		git diff >> tests/autogenerate-examples-repeat.log; \
		git reset --hard; \
		echo "----------------------------------" >> tests/autogenerate-examples-repeat.log; \
	done

update-doc-examples:
	PATH="$(DOC_EXAMPLES_PATH)" TEST_DEBUG=1 VALGRIND=0 GENERATE_EXAMPLES=1 CLN_NEXT_VERSION=$(CLN_NEXT_VERSION) $(PYTEST) $(PYTEST_OPTS) --timeout=1200 tests/autogenerate-rpc-examples.py && $(MAKE) $(MSGGEN_GEN_ALL)

# If you changed tests/autogenerate-rpc-examples.py to require new blocks, you have to run this:
update-doc-examples-newchain:
	PATH="$(DOC_EXAMPLES_PATH)" TEST_DEBUG=1 VALGRIND=0 GENERATE_EXAMPLES=1 CLN_NEXT_VERSION=$(CLN_NEXT_VERSION) REGENERATE_BLOCKCHAIN=1 $(PYTEST) $(PYTEST_OPTS) --timeout=1200 tests/autogenerate-rpc-examples.py && $(MAKE) $(MSGGEN_GEN_ALL)

check-doc-examples: update-doc-examples
	git diff --exit-code HEAD -- doc

check-wire-format: bolt-precheck
	@if [ -d .tmp.lightningrfc ]; then $(MAKE) extract-bolt-csv; else echo "Not checking BOLTs: BOLTDIR $(BOLTDIR) does not exist" >&2; fi
	git diff --exit-code HEAD -- wire

# SECURITY.md and doc/contribute-to-core-lightning/security-policy.md must be
# synced. So far we do this manually.
check-security:
	@bash -lc 'diff -u <(tail -n +3 -- SECURITY.md) <(tail -n +9 -- doc/contribute-to-core-lightning/security-policy.md)'

# This should NOT compile things!
check-source: check-makefile check-whitespace check-spelling check-python-flake8 check-includes check-shellcheck check-setup_locale check-tmpctx check-discouraged-functions check-amount-access check-bad-sprintf check-wire-format check-source-bolt check-security

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
	git diff --text --exit-code HEAD

coverage/coverage.info: check pytest
	mkdir coverage || true
	lcov --capture --directory . --output-file coverage/coverage.info

coverage: coverage/coverage.info
	genhtml coverage/coverage.info --output-directory coverage

# Clang coverage targets (source-based coverage)
coverage-clang-collect:
	@./contrib/coverage/collect-coverage.sh "$(CLN_COVERAGE_DIR)" coverage/merged.profdata

coverage-clang-report: coverage/merged.profdata
	@./contrib/coverage/generate-coverage-report.sh coverage/merged.profdata coverage/html

coverage-clang: coverage-clang-collect coverage-clang-report
	@echo "Coverage report: coverage/html/index.html"

coverage-clang-clean:
	rm -rf coverage/ "$(CLN_COVERAGE_DIR)"

.PHONY: coverage-clang-collect coverage-clang-report coverage-clang coverage-clang-clean

# Python API documentation targets
python-docs:
	@./contrib/api/generate-python-docs.py

python-docs-clean:
	rm -rf docs/python

.PHONY: python-docs python-docs-clean

# We make libwallycore.la a dependency, so that it gets built normally, without ncc.
# Ncc can't handle the libwally source code (yet).
ncc: ${TARGET_DIR}/libwally-core-build/src/libwallycore.la
	$(MAKE) CC="ncc -ncgcc -ncld -ncfabs" AR=nccar LD=nccld

# Ignore test/ directories.
TAGS:
	$(RM) TAGS; find * -name test -type d -prune -o \( -name '*.[ch]' -o -name '*.py' \) -print0 | xargs -0 etags --append

tags:
	$(RM) tags; find * -name test -type d -prune -o \( -name '*.[ch]' -o -name '*.py' \) -print0 | xargs -0 ctags --append

ALL_BUILD_PROGRAMS += $(CDUMP_ENUMSTR)
# Can't add to ALL_OBJS, as that makes a circular dep.
$(CDUMP_ENUMSTR).o: $(CCAN_HEADERS) Makefile

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

header_versions_gen.h: tools/header-versions.sh $(FORCE)
	@HAVE_SQLITE3='$(HAVE_SQLITE3)' \
		SQLITE3_CFLAGS='$(SQLITE3_CFLAGS)' \
		$< $@

# Once you have libccan.a, you don't need these.
.INTERMEDIATE: $(CCAN_OBJS)

# We make a static library, this way linker can discard unused parts.
$(BUILDDIR)/libccan.a: $(BUILDDIR)/libccan.a($(CCAN_OBJS))

# All binaries require the external libs, ccan and system library versions.
$(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS): $(EXTERNAL_LIBS) $(BUILDDIR)/libccan.a

# Each build-time program depends on its own object.
$(ALL_BUILD_PROGRAMS) $(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS): %: %.o

# Without this rule, the (built-in) link line contains
# external/libwallycore.a directly, which causes a symbol clash (it
# uses some ccan modules internally).  We want to rely on -lwallycore etc.
# (as per EXTERNAL_LDLIBS) so we filter them out here.  We have to put the other
# .a files (if any) at the end of the link line.
$(ALL_PROGRAMS) $(ALL_BUILD_PROGRAMS) $(ALL_TEST_PROGRAMS):
	@$(call VERBOSE, "ld $@", $(LINK.c) $(filter-out %.a,$^) $(filter-out external/%,$(filter %.a,$^)) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) $($(@)_LDLIBS) -o $@)
ifeq ($(OS),Darwin)
	@$(call VERBOSE, "dsymutil $@", dsymutil $@)
endif

# We special case the fuzzing target binaries, as they need to link against libfuzzer,
# which brings its own main().
# FUZZER_LIB and LLVM_LDFLAGS are set by configure script on macOS
ifneq ($(FUZZING),0)
ifeq ($(OS),Darwin)
ifneq ($(FUZZER_LIB),)
FUZZ_LDFLAGS = $(FUZZER_LIB) $(LLVM_LDFLAGS)
else
FUZZ_LDFLAGS = -fsanitize=fuzzer
endif
else
FUZZ_LDFLAGS = -fsanitize=fuzzer
endif
endif

$(ALL_FUZZ_TARGETS):
	@$(call VERBOSE, "ld $@", $(LINK.c) $(filter-out %.a,$^) $(addprefix $(BUILDDIR)/,libcommon.a libccan.a) $(LOADLIBES) $(EXTERNAL_LDLIBS) $(LDLIBS) $(FUZZ_LDFLAGS) -o $@)
ifeq ($(OS),Darwin)
	@$(call VERBOSE, "dsymutil $@", dsymutil $@)
endif


# Everything depends on the CCAN headers, and Makefile
$(CCAN_OBJS) $(CDUMP_OBJS): $(CCAN_HEADERS) Makefile ccan_compat.h

# Except for CCAN, we treat everything else as dependent on external/ bitcoin/ common/ wire/ and all generated headers, and Makefile
$(ALL_OBJS): $(BITCOIN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS) $(WIRE_HEADERS) $(ALL_GEN_HEADERS) $(EXTERNAL_HEADERS) Makefile

# Test files can literally #include generated C files.
$(ALL_TEST_PROGRAMS:=.o): $(ALL_GEN_SOURCES)

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | $(SED) s,/_info,, | $(SORT)` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ../ccan/doc/configurator.1 ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan rev-parse --short HEAD` >> ccan/README
	$(RM) -r ccan.old
	$(RM) -r ccan/ccan/hash/ ccan/ccan/tal/talloc/	# Unnecessary deps

# Now ALL_PROGRAMS is fully populated, we can expand it.
all-programs: $(ALL_PROGRAMS)
all-fuzz-programs: $(ALL_FUZZ_TARGETS)
all-test-programs: $(ALL_TEST_PROGRAMS) $(ALL_FUZZ_TARGETS)
default-targets: $(DEFAULT_TARGETS)

distclean: clean
	$(RM) ccan/config.h config.vars

maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'
	$(RM) $(PYTHON_GENERATED)

# We used to have gen_ files, now we have _gen files.
# We used to generate doc/schemas/lightning-sql.json.
# headerversions used to be a compiled program.
# Build products used to land inside the source tree.
obsclean::
	$(RM) gen_*.h */gen_*.[ch] */*/gen_*.[ch]
	$(RM) doc/schemas/lightning-sql.json
	$(RM) tools/headerversions tools/headerversions.o
	$(RM) libccan.a
	$(RM) ccan/ccan/cdump/tools/cdump-enumstr ccan/ccan/cdump/tools/cdump-enumstr.o
	$(RM) $(ALL_OBJS:$(BUILDDIR)/%=%)
	$(RM) $(ALL_PROGRAMS:$(BUILDDIR)/%=%)
	$(RM) $(ALL_TEST_PROGRAMS:$(BUILDDIR)/%=%)
	$(RM) $(ALL_FUZZ_TARGETS:$(BUILDDIR)/%=%)

clean: obsclean
	$(RM) -r $(BUILDDIR)
	$(RM) $(ALL_GEN_HEADERS) $(ALL_GEN_SOURCES)
	$(RM) $(MSGGEN_GEN_ALL)
	$(RM) ccan/tools/configurator/configurator
	find . -name '*gcda' -delete
	find . -name '*gcno' -delete
	find . -name '*.nccout' -delete
	if [ "${RUST}" -eq "1" ]; then cargo clean; fi
	rm -rf .venv


# See doc/contribute-to-core-lightning/contributor-workflow.md
PYLNS=client proto testing
update-versions: update-pyln-versions update-reckless-version update-dot-version # FIXME: update-doc-examples
	@uv lock

update-pyln-versions: $(PYLNS:%=update-pyln-version-%)

update-pyln-version-%:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	@echo "Updating contrib/pyln-$* to $(NEW_VERSION)"
	@$(SED) -i.bak 's/^version = .*/version = "$(NEW_VERSION)"/' contrib/pyln-$*/pyproject.toml && rm contrib/pyln-$*/pyproject.toml.bak
	@$(SED) -i.bak 's/^__version__ = .*/__version__ = "$(NEW_VERSION)"/' contrib/pyln-$*/pyln/$*/__init__.py && rm contrib/pyln-$*/pyln/$*/__init__.py.bak

pyln-release:  $(PYLNS:%=pyln-release-%)

pyln-release-%:
	cd contrib/pyln-$* && $(MAKE) prod-release

pyln-build: $(PYLNS:%=pyln-build-%)

pyln-build-%:
	uv build contrib/pyln-$*/

BOLT_SPECS := bolt1 bolt2 bolt4 bolt7
pyln-build-bolts: $(BOLT_SPECS:%=pyln-build-%)
	@echo "building bolt specs complete"

$(BOLT_SPECS:%=pyln-build-%) pyln-build-grpc-proto pyln-build-wss-proxy:
	@case $@ in \
		pyln-build-grpc-proto) uv build contrib/pyln-grpc-proto/ ;; \
		pyln-build-bolt*) uv build contrib/pyln-spec/$(patsubst pyln-build-%,%,$@)/ ;; \
		pyln-build-wss-proxy) uv build plugins/wss-proxy/ ;; \
	esac

pyln-build-all: pyln-build pyln-build-bolts pyln-build-grpc-proto pyln-build-wss-proxy
	@echo "building python packages complete"

update-lock:
	uv sync --all-extras --all-groups

update-reckless-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	@echo "Updating tools/reckless to $(NEW_VERSION)"
	@$(SED) -i.bak "s/__VERSION__ = '.*'/__VERSION__ = '$(NEW_VERSION)'/" tools/reckless && rm tools/reckless.bak

update-dot-version:
	@if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	echo $(NEW_VERSION) > .version

update-mocks: $(ALL_TEST_PROGRAMS:%=update-mocks/%.c)

$(ALL_TEST_PROGRAMS:%=update-mocks/%.c): $(ALL_GEN_HEADERS) $(EXTERNAL_LIBS) $(BUILDDIR)/libccan.a $(CDUMP_ENUMSTR) config.vars

update-mocks/%: % $(ALL_GEN_HEADERS) $(ALL_GEN_SOURCES)
	@MAKE=$(MAKE) SED=$(SED) tools/update-mocks.sh "$*" $(SUPPRESS_OUTPUT)

unittest/%: % bolt-precheck
	BOLTDIR=$(LOCAL_BOLTDIR) $(VG) $(VG_TEST_ARGS) $* > /dev/null

# FIXME: we don't do leak detection on fuzz tests, since they don't have a cleanup function.
fuzzunittest/%: % bolt-precheck
	BOLTDIR=$(LOCAL_BOLTDIR) $(VG) $* > /dev/null

# Commands
MKDIR_P = mkdir -p
RMDIR_P = rmdir -p
CP_A = cp -a
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# $(1) = install command
# $(2) = installation source file
# $(3) = installation target file
define INSTALL_RULE_tmpl =
$(3): $(2) | $(dir $(3))
	@$$(call VERBOSE,"install $$@",$(1) $$< $$|)
endef

# $(1) = install command
# $(2) = list of files to install to $(3)
# $(3) = installation target directory
install_targets = $(foreach f,$(2),$(let t,$(3)/$(notdir $(f)),$(eval $(call INSTALL_RULE_tmpl,$(1),$(f),$(t)))$(t)))

# $(1) = list of files to install to $(2)
# $(2) = installation target directory
install_program_targets = $(call install_targets,$(INSTALL_PROGRAM),$(1),$(2))
install_data_targets = $(call install_targets,$(INSTALL_DATA),$(1),$(2))

# Defines a rule that touches $(1) whenever it is older than any file listed in $(2).
define TOUCH_RULE_tmpl =
$(1): $(2)
	@touch $(1)
endef

# $(1) = list of files whose containing directories are to be installed to $(2)
# $(2) = installation target directory
# An installation target rule is defined for each distinct directory containing
# any file listed in $(1). A containing directory will be touched whenever any
# listed contained file is newer than it. The touched directory then will
# trigger a re-installation of the whole directory.
install_py_plugin_targets = $(foreach d,$(sort $(dir $(1))),$(let t,$(2)/$(notdir $(patsubst %/,%,$(d))),$(eval $(call TOUCH_RULE_tmpl,$(d),$(filter $(d)%,$(1))))$(eval $(call INSTALL_RULE_tmpl,$(RM) -r $$@ && $(CP_A),$(d),$(t)))$(t)))

# Tags needed by some package systems.
PRE_INSTALL = :
NORMAL_INSTALL = :
POST_INSTALL = :
PRE_UNINSTALL = :
NORMAL_UNINSTALL = :
POST_UNINSTALL = :

$(DESTDIR)$(plugindir)/clnrest: uninstall-old-clnrest-plugin
uninstall-old-clnrest-plugin:
	@[ -d $(DESTDIR)$(plugindir)/clnrest ] && $(RM) -r $(DESTDIR)$(plugindir)/clnrest

$(DESTDIR)$(plugindir)/wss-proxy: uninstall-old-wss-proxy-plugin
uninstall-old-wss-proxy-plugin:
	@[ -d $(DESTDIR)$(plugindir)/wss-proxy ] && $(RM) -r $(DESTDIR)$(plugindir)/wss-proxy

.PHONY: uninstall-old-clnrest-plugin uninstall-old-wss-proxy-plugin

# $(PLUGINS) is defined in plugins/Makefile.

INSTALL_PROGRAM_TARGETS := \
	$(call install_program_targets,$(BIN_PROGRAMS),$(DESTDIR)$(bindir)) \
	$(call install_program_targets,$(PKGLIBEXEC_PROGRAMS),$(DESTDIR)$(pkglibexecdir)) \
	$(call install_program_targets,$(PLUGINS),$(DESTDIR)$(plugindir)) \
	$(call install_py_plugin_targets,$(PY_PLUGINS),$(DESTDIR)$(plugindir))

install-program: $(INSTALL_PROGRAM_TARGETS)
	@$(NORMAL_INSTALL)
ifeq ($(OS),Darwin)
	# Install dSYM bundles alongside binaries on macOS
	for BIN in $(BIN_PROGRAMS); do if [ -d $$BIN.dSYM ]; then cp -a $$BIN.dSYM $(DESTDIR)$(bindir)/; fi; done
	for BIN in $(PKGLIBEXEC_PROGRAMS); do if [ -d $$BIN.dSYM ]; then cp -a $$BIN.dSYM $(DESTDIR)$(pkglibexecdir)/; fi; done
	for PLUGIN in $(PLUGINS); do if [ -d $$PLUGIN.dSYM ]; then cp -a $$PLUGIN.dSYM $(DESTDIR)$(plugindir)/; fi; done
endif

MAN1PAGES = $(filter %.1,$(MANPAGES))
MAN5PAGES = $(filter %.5,$(MANPAGES))
MAN7PAGES = $(filter %.7,$(MANPAGES))
MAN8PAGES = $(filter %.8,$(MANPAGES))
DOC_DATA = README.md LICENSE

INSTALL_DATA_TARGETS := \
	$(call install_data_targets,$(MAN1PAGES),$(DESTDIR)$(man1dir)) \
	$(call install_data_targets,$(MAN5PAGES),$(DESTDIR)$(man5dir)) \
	$(call install_data_targets,$(MAN7PAGES),$(DESTDIR)$(man7dir)) \
	$(call install_data_targets,$(MAN8PAGES),$(DESTDIR)$(man8dir)) \
	$(call install_data_targets,$(DOC_DATA),$(DESTDIR)$(docdir))

install-data: $(INSTALL_DATA_TARGETS)
	@$(NORMAL_INSTALL)

install: install-program install-data

# We exclude most of target/ and external, but we need:
# 1. config files (we only tar up files *newer* than these)
# 2. $(DEFAULT_TARGETS) for rust stuff.
# 3. $(EXTERNAL_LIBS) for prebuild external libraries.
TESTPACK_EXTRAS :=			\
	config.vars ccan/config.h	\
	header_versions_gen.h		\
	$(DEFAULT_TARGETS)		\
	$(EXTERNAL_LIBS)

# The testpack is used in CI to transfer built artefacts between the
# build and the test phase.  Only useful on a freshly build tree!
# We use Posix format for timestamps with subsecond accuracy.
testpack.tar.gz: all-programs all-fuzz-programs all-test-programs default-targets
	(find * -path external -prune -o -path target -prune -o -newer config.vars -type f -print; ls $(TESTPACK_EXTRAS)) | tar --verbatim-files-from -T- -c --format=posix -f - | gzip -5 > $@

uninstall-program:
	@$(NORMAL_UNINSTALL)
ifneq ($(strip $(INSTALL_PROGRAM_TARGETS)),)
	$(RM) -r $(INSTALL_PROGRAM_TARGETS)
	$(RMDIR_P) $(sort $(dir $(INSTALL_PROGRAM_TARGETS))) 2>/dev/null || :
endif

uninstall-data:
	@$(NORMAL_UNINSTALL)
ifneq ($(strip $(INSTALL_DATA_TARGETS)),)
	$(RM) -r $(INSTALL_DATA_TARGETS)
	$(RMDIR_P) $(sort $(dir $(INSTALL_DATA_TARGETS))) 2>/dev/null || :
endif

uninstall: uninstall-program uninstall-data

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

version:
	@echo ${VERSION}

.PHONY: install-program install-data install uninstall-program uninstall-data uninstall \
	installcheck ncc bin-tarball show-flags version

# Make a tarball of opt/clightning/, optionally with label for distribution.
ifneq ($(VERSION),)
bin-tarball: clightning-$(VERSION)-$(DISTRO).tar.xz
clightning-$(VERSION)-$(DISTRO).tar.xz: DESTDIR=$(shell pwd)/
clightning-$(VERSION)-$(DISTRO).tar.xz: prefix=opt/clightning
clightning-$(VERSION)-$(DISTRO).tar.xz: install
	trap "rm -rf opt" 0; tar cvfa $@ opt/
endif


canned-gossmap: devtools/gossmap-compress
	DATE=`date +%Y-%m-%d` && devtools/gossmap-compress compress --output-node-map /tmp/gossip_store tests/data/gossip-store-$$DATE.compressed > tests/data/gossip-store-$$DATE-node-map && xz -9 tests/data/gossip-store-$$DATE-node-map && ls -l tests/data/gossip-store-$$DATE*

print-binary-sizes: $(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS) $(BIN_PROGRAMS)
	@echo User programs:
	@size -t $(PKGLIBEXEC_PROGRAMS) $(filter-out tools/reckless,$(BIN_PROGRAMS)) $(PLUGINS)
	@echo All programs:
	@size -t $(ALL_PROGRAMS) $(ALL_TEST_PROGRAMS) | tail -n1

.SECONDEXPANSION:
# All rules beyond this point are subject to secondary expansion of their prerequisites!

$(BUILDDIR)/%.o: %.c | $$(@D)/
	@$(call VERBOSE,"cc $<",$(COMPILE.c) -o $@ $<)
