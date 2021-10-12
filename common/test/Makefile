COMMON_TEST_SRC := $(wildcard common/test/run-*.c)

ifeq ($(EXPERIMENTAL_FEATURES),1)
COMMON_TEST_SRC += $(wildcard common/test/exp-run-*.c)
endif

COMMON_TEST_OBJS := $(COMMON_TEST_SRC:.c=.o)
COMMON_TEST_PROGRAMS := $(COMMON_TEST_OBJS:.o=)

COMMON_TEST_COMMON_OBJS :=				\
	common/autodata.o				\
	common/setup.o					\
	common/utils.o

$(COMMON_TEST_PROGRAMS): $(COMMON_TEST_COMMON_OBJS) $(BITCOIN_OBJS)
$(COMMON_TEST_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC)

ALL_C_SOURCES += $(COMMON_TEST_SRC)
ALL_TEST_PROGRAMS += $(COMMON_TEST_PROGRAMS)

# Sphinx test wants to decode TLVs.
common/test/run-sphinx: wire/onion$(EXP)_wiregen.o wire/towire.o wire/fromwire.o
common/test/run-blindedpath_enctlv common/test/run-blindedpath_onion: common/base32.o common/wireaddr.o wire/onion$(EXP)_wiregen.o wire/peer$(EXP)_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o
common/test/run-route_blinding_test: wire/onion$(EXP)_wiregen.o wire/peer$(EXP)_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o common/json.o common/json_helpers.o
common/test/run-route_blinding_override_test: common/base32.o common/wireaddr.o wire/onion$(EXP)_wiregen.o wire/peer$(EXP)_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o common/json.o common/json_helpers.o

common/test/run-param					\
common/test/run-json:					\
	common/amount.o					\
	common/base32.o					\
	common/bigsize.o				\
	common/channel_id.o				\
	common/json.o					\
	common/json_stream.o				\
	common/lease_rates.o				\
	common/node_id.o				\
	common/pseudorand.o				\
	common/type_to_string.o				\
	common/wireaddr.o				\
	wire/fromwire.o					\
	wire/onion$(EXP)_wiregen.o			\
	wire/peer$(EXP)_wiregen.o			\
	wire/towire.o

common/test/run-route common/test/run-route-specific:	\
	common/amount.o					\
	common/dijkstra.o				\
	common/fp16.o				\
	common/gossmap.o				\
	common/node_id.o				\
	common/pseudorand.o				\
	common/route.o					\
	wire/fromwire.o					\
	wire/peer$(EXP)_wiregen.o			\
	wire/towire.o

common/test/run-gossmap_local:				\
	common/base32.o					\
	common/wireaddr.o				\
	wire/fromwire.o					\
	wire/peer$(EXP)_wiregen.o			\
	wire/tlvstream.o				\
	wire/towire.o

common/test/run-bolt12_merkle:				\
	common/amount.o					\
	common/bigsize.o				\
	common/base32.o					\
	common/bech32.o					\
	common/bech32_util.o				\
	common/bolt12.o					\
	common/node_id.o				\
	common/type_to_string.o				\
	common/wireaddr.o				\
	wire/bolt12$(EXP)_wiregen.o			\
	wire/fromwire.o					\
	wire/tlvstream.o				\
	wire/peer$(EXP)_wiregen.o			\
	wire/towire.o

common/test/run-bolt12_merkle-json:			\
	common/base32.o					\
	common/wireaddr.o

check-units: $(COMMON_TEST_PROGRAMS:%=unittest/%)
