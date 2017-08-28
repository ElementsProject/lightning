# FIXME: Move to common/test
COMMON_TEST_PROGRAMS :=					\
	common/test/test_sphinx

COMMON_TEST_COMMON_OBJS :=				\
	common/sphinx.o					\
	common/utils.o

$(COMMON_TEST_PROGRAMS): $(TEST_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

ALL_TEST_PROGRAMS += $(COMMON_TEST_PROGRAMS)
ALL_OBJS += $(COMMON_TEST_PROGRAMS:=.o)

