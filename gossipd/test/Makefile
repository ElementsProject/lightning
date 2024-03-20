check-units: gossipd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
GOSSIPD_TEST_SRC := $(wildcard gossipd/test/run-*.c)
GOSSIPD_TEST_OBJS := $(GOSSIPD_TEST_SRC:.c=.o)
GOSSIPD_TEST_PROGRAMS := $(GOSSIPD_TEST_OBJS:.o=)

GOSSIPD_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/coin_mvt.o			\
	common/bigsize.o			\
	common/blindedpath.o			\
	common/channel_id.o			\
	common/features.o			\
	common/hmac.o				\
	common/node_id.o			\
	common/lease_rates.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/utils.o				\
	common/wireaddr.o			\
	gossipd/gossip_store_wiregen.o		\
	wire/peer_wiregen.o			\
	wire/onion_wiregen.o			\
	wire/fromwire.o				\
	wire/tlvstream.o			\
	wire/towire.o

ALL_C_SOURCES += $(GOSSIPD_TEST_SRC)
ALL_TEST_PROGRAMS += $(GOSSIPD_TEST_PROGRAMS)

# Extra stuff needed for onion tests
gossipd/test/run-onion_message:			\
	wire/onion_wiregen.o			\
	common/blindedpath.o			\
	common/blinding.o			\
	common/hmac.o				\
	common/sphinx.o				\

# JSON needed for this test
gossipd/test/run-extended-info:			\
	common/json_parse.o			\
	common/json_parse_simple.o

$(GOSSIPD_TEST_PROGRAMS): $(GOSSIPD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(GOSSIPD_TEST_OBJS): $(GOSSIPD_HEADERS) $(GOSSIPD_SRC)

gossipd-tests: $(GOSSIPD_TEST_PROGRAMS:%=unittest/%)
