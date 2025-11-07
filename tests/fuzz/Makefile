LIBFUZZ_SRC := tests/fuzz/libfuzz.c
LIBFUZZ_HEADERS := $(LIBFUZZ_SRC:.c=.h)
LIBFUZZ_OBJS := $(LIBFUZZ_SRC:.c=.o)

tests/fuzz/fuzz-connectd-handshake-act*.o: tests/fuzz/connectd_handshake.h
tests/fuzz/fuzz-ripemd160: LDLIBS += -lcrypto
tests/fuzz/fuzz-sha256: LDLIBS += -lcrypto
tests/fuzz/fuzz-hmac-sha256: LDLIBS += -lcrypto
tests/fuzz/fuzz-wire-*.o: tests/fuzz/wire.h
tests/fuzz/fuzz-bolt12-*.o: tests/fuzz/bolt12.h

tests/fuzz/fuzz-gossipd-connectd: gossipd/gossipd_wiregen.o		\
				  gossipd/gossip_store_wiregen.o	\
				  gossipd/gossip_store.o		\
				  gossipd/queries.o			\
				  gossipd/sigcheck.o			\
				  gossipd/txout_failures.o		\
				  common/wire_error.o			\
				  common/gossmap.o			\
				  common/gossip_store.o			\
				  common/gossmods_listpeerchannels.o	\
				  common/timeout.o			\
				  common/fp16.o				\
				  common/decode_array.o			\
				  connectd/connectd_gossipd_wiregen.o

FUZZ_TARGETS_SRC := $(wildcard tests/fuzz/fuzz-*.c)
FUZZ_TARGETS_OBJS := $(FUZZ_TARGETS_SRC:.c=.o)
FUZZ_TARGETS_BIN := $(FUZZ_TARGETS_SRC:.c=)

$(FUZZ_TARGETS_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC) tests/fuzz/libfuzz.h
$(FUZZ_TARGETS_BIN): $(LIBFUZZ_OBJS) libcommon.a

ALL_C_SOURCES += $(FUZZ_TARGETS_SRC) $(LIBFUZZ_SRC)
ALL_FUZZ_TARGETS += $(FUZZ_TARGETS_BIN)

# In non-fuzzing builds, these become normal tests.
ifneq ($(FUZZING),1)
check-units: $(FUZZ_TARGETS_BIN:%=fuzzunittest/%)
endif
