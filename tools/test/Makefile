#! /usr/bin/make
#
# Rudimentary tests for the wire parsers, using a set of test
# definitions. (Covers more of the test definitions)
#
# We generate the files, and then we attempt to compile
# and run a test case.
check-units: check-tools

TOOL_GEN_SRC := tools/test/gen_test.c tools/test/gen_print.c
TOOL_GEN_HEADER := tools/test/gen_test.h tools/test/gen_print.h
TOOL_TEST_SRC := $(wildcard tools/test/run-*.c)
TOOL_TEST_OBJS := $(TOOL_TEST_SRC:.c=.o)
TOOL_TEST_PROGRAMS := $(TOOL_TEST_OBJS:.o=)

TOOL_TEST_COMMON_OBJS :=		\
	common/utils.o

TOOLS_WIRE_DEPS := $(BOLT_DEPS) tools/test/test_cases $(wildcard tools/gen/*_template)

$(TOOL_TEST_SRC) $(TOOL_GEN_SRC): $(TOOL_GEN_HEADER)
$(TOOL_TEST_OBJS): $(TOOL_GEN_SRC)
$(TOOL_TEST_PROGRAMS): $(TOOL_TEST_COMMON_OBJS) $(TOOL_GEN_SRC:.c=.o)
$(TOOL_GEN_SRC) $(TOOL_GEN_HEADER): $(TOOLS_WIRE_DEPS)

tools/test/gen_test.h:
	tools/generate-bolts.py --page header $@ test_type < tools/test/test_cases > $@

tools/test/gen_test.c:
	tools/generate-bolts.py --page impl ${@:.c=.h} test_type < tools/test/test_cases > $@
	@tools/update-mocks.sh "$@"

tools/test/gen_print.h: wire/gen_onion_wire.h
	tools/generate-bolts.py -P --page header $@ test_type < tools/test/test_cases > $@

tools/test/gen_print.c:
	echo '#include "gen_test.h"' > $@
	tools/generate-bolts.py -P --page impl ${@:.c=.h} test_type < tools/test/test_cases >> $@


ALL_TEST_PROGRAMS += $(TOOL_TEST_PROGRAMS)

check-tools: $(TOOL_TEST_PROGRAMS:%=unittest/%)

update-mocks: tools-update-mocks

tools-update-mocks: $(TOOL_TEST_SRC:%=update-mocks/%)

clean: tools-test-clean

tools-test-clean:
	$(RM) $(TOOL_GEN_HEADER) $(TOOL_GEN_SRC) $(TOOL_TEST_OBJS)
