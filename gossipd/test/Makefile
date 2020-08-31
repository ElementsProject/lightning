check-units: gossipd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
GOSSIPD_TEST_SRC := $(wildcard gossipd/test/run-*.c)
GOSSIPD_TEST_OBJS := $(GOSSIPD_TEST_SRC:.c=.o)
GOSSIPD_TEST_PROGRAMS := $(GOSSIPD_TEST_OBJS:.o=)

GOSSIPD_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/bigsize.o			\
	common/channel_id.o			\
	common/features.o			\
	common/node_id.o			\
	common/json.o				\
	common/json_helpers.o			\
	common/pseudorand.o			\
	common/type_to_string.o			\
	common/utils.o				\
	wire/peer_wiregen.o			\
	wire/fromwire.o				\
	wire/towire.o

update-mocks: $(GOSSIPD_TEST_SRC:%=update-mocks/%)

$(GOSSIPD_TEST_PROGRAMS): $(GOSSIPD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(GOSSIPD_TEST_OBJS): $(LIGHTNINGD_GOSSIP_HEADERS) $(LIGHTNINGD_GOSSIP_SRC)

ALL_OBJS += $(GOSSIPD_TEST_OBJS)
ALL_TEST_PROGRAMS += $(GOSSIPD_TEST_PROGRAMS)

gossipd-tests: $(GOSSIPD_TEST_PROGRAMS:%=unittest/%)

