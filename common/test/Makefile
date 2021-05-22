COMMON_TEST_SRC := $(wildcard common/test/run-*.c)

ifeq ($(EXPERIMENTAL_FEATURES),1)
COMMON_TEST_SRC += $(wildcard common/test/exp-run-*.c)
endif

COMMON_TEST_OBJS := $(COMMON_TEST_SRC:.c=.o)
COMMON_TEST_PROGRAMS := $(COMMON_TEST_OBJS:.o=)

COMMON_TEST_COMMON_OBJS :=				\
	common/setup.o					\
	common/utils.o

$(COMMON_TEST_PROGRAMS): $(COMMON_TEST_COMMON_OBJS) $(BITCOIN_OBJS)
$(COMMON_TEST_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC)

ALL_C_SOURCES += $(COMMON_TEST_SRC)
ALL_TEST_PROGRAMS += $(COMMON_TEST_PROGRAMS)

# Sphinx test wants to decode TLVs.
common/test/run-sphinx: wire/onion$(EXP)_wiregen.o wire/towire.o wire/fromwire.o

common/test/run-param					\
common/test/run-json:					\
	common/amount.o					\
	common/base32.o					\
	common/bigsize.o				\
	common/json.o					\
	common/json_stream.o				\
	common/wireaddr.o				\
	common/type_to_string.o				\
	wire/fromwire.o					\
	wire/onion$(EXP)_wiregen.o			\
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
	wire/fromwire.o					\
	wire/peer$(EXP)_wiregen.o			\
	wire/towire.o

check-units: $(COMMON_TEST_PROGRAMS:%=unittest/%)
