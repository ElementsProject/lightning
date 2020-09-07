LIBFUZZ_SRC := tests/fuzz/libfuzz.c
LIBFUZZ_HEADERS := $(LIBFUZZ_SRC:.c=.h)
LIBFUZZ_OBJS := $(LIBFUZZ_SRC:.c=.o)


FUZZ_TARGETS_SRC := $(wildcard tests/fuzz/fuzz-*.c)
FUZZ_TARGETS_OBJS := $(FUZZ_TARGETS_SRC:.c=.o)
FUZZ_TARGETS_BIN := $(FUZZ_TARGETS_SRC:.c=)

FUZZ_COMMON_OBJS :=			\
	common/utils.o
$(FUZZ_TARGETS_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC)
$(FUZZ_TARGETS_BIN): $(LIBFUZZ_OBJS) $(FUZZ_COMMON_OBJS) $(BITCOIN_OBJS)

tests/fuzz/fuzz-addr:					\
	common/amount.o					\
	common/addr.o					\
	common/base32.o					\
	common/bech32.o					\
	common/bigsize.o				\
	common/json.o					\
	common/json_stream.o				\
	common/wireaddr.o				\
	common/type_to_string.o				\
	wire/fromwire.o					\
	wire/onion_wiregen.o				\
	wire/towire.o

ALL_C_SOURCES += $(FUZZ_TARGETS_SRC) $(LIBFUZZ_SRC)
ALL_FUZZ_TARGETS += $(FUZZ_TARGETS_BIN)
