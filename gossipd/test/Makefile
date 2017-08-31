check: gossipd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
GOSSIPD_TEST_SRC := $(wildcard gossipd/test/run-*.c)
GOSSIPD_TEST_OBJS := $(GOSSIPD_TEST_SRC:.c=.o)
GOSSIPD_TEST_PROGRAMS := $(GOSSIPD_TEST_OBJS:.o=)

GOSSIPD_TEST_COMMON_OBJS :=			\
	common/pseudorand.o			\
	common/type_to_string.o			\
	common/utils.o

update-mocks: $(GOSSIPD_TEST_SRC:%=update-mocks/%)

$(GOSSIPD_TEST_PROGRAMS): $(GOSSIPD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects require source to be generated, since they include ..
$(GOSSIPD_TEST_OBJS): $(GOSSIPD_GEN_SRC) $(LIGHTNINGD_GOSSIP_SRC)

ALL_OBJS += $(GOSSIPD_TEST_OBJS)
ALL_TEST_PROGRAMS += $(GOSSIPD_TEST_PROGRAMS)

gossipd-tests: $(GOSSIPD_TEST_PROGRAMS:%=unittest/%)

