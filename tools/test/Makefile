#! /usr/bin/make
#
# Rudimentary tests for the wire parsers, using a set of test
# definitions. (Covers more of the test definitions)
#
# We generate the files, and then we attempt to compile
# and run a test case.

# We don't run these at all unless mako is installed.
ifeq ($(HAVE_PYTHON3_MAKO),1)
check-units: check-tools

TOOL_TEST_INCL_SRC := tools/test/enum.c
TOOL_GEN_SRC := tools/test/test_gen.c tools/test/print_gen.c
TOOL_GEN_OBJS := $(TOOL_GEN_SRC:.c=.o)
TOOL_GEN_HEADER := tools/test/test_gen.h tools/test/print_gen.h
# Don't require update-mocks hack unless developer mode.
ifeq ($(DEVELOPER),1)
TOOL_TEST_SRC := $(wildcard tools/test/run-*.c)
else
TOOL_TEST_SRC :=
endif
TOOL_TEST_OBJS := $(TOOL_TEST_SRC:.c=.o)
TOOL_TEST_PROGRAMS := $(TOOL_TEST_OBJS:.o=)

# Get dependencies correct
ALL_C_SOURCES += $(TOOL_GEN_SRC) $(TOOL_TEST_SRC)
ALL_C_HEADERS += $(TOOL_GEN_HEADER)

TOOL_TEST_COMMON_OBJS :=		\
	common/utils.o

TOOLS_WIRE_DEPS := $(BOLT_DEPS) tools/test/test_cases $(wildcard tools/gen/*_template)

$(TOOL_TEST_OBJS) $(TOOL_GEN_OBJS): $(TOOL_GEN_HEADER)
$(TOOL_TEST_PROGRAMS): $(TOOL_TEST_COMMON_OBJS) $(TOOL_GEN_SRC:.c=.o) tools/test/enum.o

tools/test/test_gen.h: $(TOOLS_WIRE_DEPS) tools/test/Makefile
	$(BOLT_GEN) --page header $@ test_type < tools/test/test_cases > $@

.INTERMEDIATE: tools/test/test_gen.c.tmp.c
# Parallel make sometimes tries to use file before update-mocks, so split.
tools/test/test_gen.c.tmp.c: $(TOOLS_WIRE_DEPS)
	$(BOLT_GEN) --page impl tools/test/test_gen.h test_type < tools/test/test_cases > $@

tools/test/test_gen.c: tools/test/test_gen.c.tmp.c $(EXTERNAL_HEADERS) tools/test/test_gen.h $(CCAN_HEADERS)
	@MAKE=$(MAKE) tools/update-mocks.sh "$<" $(SUPPRESS_OUTPUT) && mv "$<" "$@"

tools/test/print_gen.h: wire/onion$(EXP)_wiregen.h $(TOOLS_WIRE_DEPS)
	$(BOLT_GEN) -P --page header $@ test_type < tools/test/test_cases > $@

tools/test/print_gen.c: $(TOOLS_WIRE_DEPS)
	echo '#include "test_gen.h"' > $@
	$(BOLT_GEN) -P --page impl ${@:.c=.h} test_type < tools/test/test_cases >> $@

ALL_TEST_PROGRAMS += $(TOOL_TEST_PROGRAMS)

check-tools: $(TOOL_TEST_PROGRAMS:%=unittest/%)
endif # HAVE_PYTHON3_MAKO

clean: tools-test-clean

tools-test-clean:
	$(RM) $(TOOL_GEN_HEADER) $(TOOL_GEN_SRC) $(TOOL_TEST_OBJS) $(TOOL_TEST_PROGRAMS)
	$(RM) $(TOOL_GEN_SRC:.c=.o) tools/test/enum.o
