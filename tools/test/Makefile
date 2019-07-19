#! /usr/bin/make
#
# Rudimentary tests for the wire parsers, using a set of test
# definitions. (Covers more of the test definitions)
#
# We generate the files, and then we attempt to compile
# and run a test case.
check-units: check-tools

TOOL_GEN_SRC := tools/test/gen_test.c
TOOL_GEN_HEADER := tools/test/gen_test.h
TOOL_TEST_SRC := $(wildcard tools/test/run-*.c)
TOOL_TEST_OBJS := $(TOOL_TEST_SRC:.c=.o)
TOOL_TEST_PROGRAMS := $(TOOL_TEST_OBJS:.o=)

TOOL_TEST_COMMON_OBJS :=		\
	common/utils.o

TOOLS_WIRE_DEPS := $(BOLT_DEPS) tools/test/test_cases $(wildcard tools/gen/*_template)

$(TOOL_TEST_SRC): $(TOOL_GEN_HEADER)
$(TOOL_TEST_OBJS): $(TOOL_GEN_SRC)
$(TOOL_TEST_PROGRAMS): $(TOOL_TEST_COMMON_OBJS)
$(TOOL_GEN_SRC) $(TOOL_GEN_HEADER): $(TOOLS_WIRE_DEPS)

tools/test/gen_test.h:
	tools/generate-bolts.py --page header $@ test_type < tools/test/test_cases > $@

tools/test/gen_test.c:
	tools/generate-bolts.py --page impl ${@:.c=.h} test_type < tools/test/test_cases > $@
	@tools/update-mocks.sh "$@"

ALL_TEST_PROGRAMS += $(TOOL_TEST_PROGRAMS)

check-tools: $(TOOL_TEST_PROGRAMS:%=unittest/%)

clean: tools-test-clean

tools-test-clean:
	$(RM) $(TOOL_GEN_FILES) $(TOOL_TEST_OBJS)
