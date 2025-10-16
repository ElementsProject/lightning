LIBFUZZ_SRC := tests/fuzz/libfuzz.c
LIBFUZZ_HEADERS := $(LIBFUZZ_SRC:.c=.h)
LIBFUZZ_OBJS := $(LIBFUZZ_SRC:.c=.o)

tests/fuzz/fuzz-connectd-handshake-act*.o: tests/fuzz/connectd_handshake.h
tests/fuzz/fuzz-ripemd160: LDLIBS += -lcrypto
tests/fuzz/fuzz-sha256: LDLIBS += -lcrypto
tests/fuzz/fuzz-hmac-sha256: LDLIBS += -lcrypto
tests/fuzz/fuzz-wire-*.o: tests/fuzz/wire.h
tests/fuzz/fuzz-bolt12-*.o: tests/fuzz/bolt12.h

FUZZ_TARGETS_SRC := $(wildcard tests/fuzz/fuzz-*.c)
FUZZ_TARGETS_OBJS := $(FUZZ_TARGETS_SRC:.c=.o)
FUZZ_TARGETS_BIN := $(FUZZ_TARGETS_SRC:.c=)

$(FUZZ_TARGETS_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC)
$(FUZZ_TARGETS_BIN): $(LIBFUZZ_OBJS) libcommon.a

ALL_C_SOURCES += $(FUZZ_TARGETS_SRC) $(LIBFUZZ_SRC)
ALL_FUZZ_TARGETS += $(FUZZ_TARGETS_BIN)
