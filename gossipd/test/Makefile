check-units: gossipd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
GOSSIPD_TEST_SRC := $(wildcard gossipd/test/run-*.c)
GOSSIPD_TEST_OBJS := $(GOSSIPD_TEST_SRC:.c=.o)
GOSSIPD_TEST_PROGRAMS := $(GOSSIPD_TEST_OBJS:.o=)

GOSSIPD_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/bigsize.o			\
	common/blindedpath.o			\
	common/channel_id.o			\
	common/features.o			\
	common/hmac.o				\
	common/node_id.o			\
	common/json.o				\
	common/json_helpers.o			\
	common/lease_rates.o			\
	common/onion.o				\
	common/pseudorand.o			\
	common/setup.o				\
	common/sphinx.o				\
	common/type_to_string.o			\
	common/utils.o				\
	gossipd/gossip_store_wiregen.o		\
	wire/peer$(EXP)_wiregen.o		\
	wire/onion$(EXP)_wiregen.o		\
	wire/fromwire.o				\
	wire/tlvstream.o			\
	wire/towire.o

ALL_C_SOURCES += $(GOSSIPD_TEST_SRC)
ALL_TEST_PROGRAMS += $(GOSSIPD_TEST_PROGRAMS)

# Extra stuff needed for onion tests
gossipd/test/run-onion_message:			\
	wire/onion$(EXP)_wiregen.o		\
	common/blindedpath.o			\
	common/blinding.o			\
	common/hmac.o				\
	common/onion.o				\
	common/sphinx.o				\


$(GOSSIPD_TEST_PROGRAMS): $(GOSSIPD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(GOSSIPD_TEST_OBJS): $(GOSSIPD_HEADERS) $(GOSSIPD_SRC)

gossipd-tests: $(GOSSIPD_TEST_PROGRAMS:%=unittest/%)

