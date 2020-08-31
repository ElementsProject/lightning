#! /usr/bin/make
#
# Rudimentary tests for the wire parsers, using a set of test
# definitions. (Covers more of the test definitions)
#
# We generate the files, and then we attempt to compile
# and run a test case.
check-units: check-tools

TOOL_TEST_INCL_SRC := tools/test/enum.c
TOOL_GEN_SRC := tools/test/gen_test.c tools/test/gen_print.c
TOOL_GEN_OBJS := $(TOOL_GEN_SRC:.c=.o)
TOOL_GEN_HEADER := tools/test/gen_test.h tools/test/gen_print.h
TOOL_TEST_SRC := $(wildcard tools/test/run-*.c)
TOOL_TEST_OBJS := $(TOOL_TEST_SRC:.c=.o)
# Don't require update-mocks hack unless developer mode.
ifeq ($(DEVELOPER),1)
TOOL_TEST_PROGRAMS := $(TOOL_TEST_OBJS:.o=)
else
TOOL_TEST_PROGRAMS :=
endif

TOOL_TEST_COMMON_OBJS :=		\
	common/utils.o

TOOLS_WIRE_DEPS := $(BOLT_DEPS) tools/test/test_cases $(wildcard tools/gen/*_template)

$(TOOL_TEST_OBJS) $(TOOL_GEN_OBJS): $(TOOL_GEN_HEADER)
$(TOOL_TEST_PROGRAMS): $(TOOL_TEST_COMMON_OBJS) $(TOOL_GEN_SRC:.c=.o) tools/test/enum.o

tools/test/gen_test.h: $(TOOLS_WIRE_DEPS) tools/test/Makefile
	$(BOLT_GEN) --page header $@ test_type < tools/test/test_cases > $@

.INTERMEDIATE: tools/test/gen_test.c.tmp.c
# Parallel make sometimes tries to use file before update-mocks, so split.
tools/test/gen_test.c.tmp.c: $(TOOLS_WIRE_DEPS)
	$(BOLT_GEN) --page impl tools/test/gen_test.h test_type < tools/test/test_cases > $@

tools/test/gen_test.c: tools/test/gen_test.c.tmp.c $(EXTERNAL_HEADERS) tools/test/gen_test.h
	@MAKE=$(MAKE) tools/update-mocks.sh "$<" $(SUPPRESS_OUTPUT) && mv "$<" "$@"

tools/test/gen_print.h: wire/onion_wiregen.h $(TOOLS_WIRE_DEPS)
	$(BOLT_GEN) -P --page header $@ test_type < tools/test/test_cases > $@

tools/test/gen_print.c: $(TOOLS_WIRE_DEPS)
	echo '#include "gen_test.h"' > $@
	$(BOLT_GEN) -P --page impl ${@:.c=.h} test_type < tools/test/test_cases >> $@

ALL_TEST_PROGRAMS += $(TOOL_TEST_PROGRAMS)

check-tools: $(TOOL_TEST_PROGRAMS:%=unittest/%)

update-mocks: tools-update-mocks

tools-update-mocks: $(TOOL_TEST_SRC:%=update-mocks/%)

clean: tools-test-clean

tools-test-clean:
	$(RM) $(TOOL_GEN_HEADER) $(TOOL_GEN_SRC) $(TOOL_TEST_OBJS) $(TOOL_TEST_PROGRAMS)
	$(RM) $(TOOL_GEN_SRC:.c=.o) tools/test/enum.o
