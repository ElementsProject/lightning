LIBFUZZ_SRC := tests/fuzz/libfuzz.c
LIBFUZZ_HEADERS := $(LIBFUZZ_SRC:.c=.h)
LIBFUZZ_OBJS := $(LIBFUZZ_SRC:%.c=$(BUILDDIR)/%.o)

$(BUILDDIR)/tests/fuzz/fuzz-connectd-handshake-act*.o: tests/fuzz/connectd_handshake.h
$(BUILDDIR)/tests/fuzz/fuzz-ripemd160: LDLIBS += -lcrypto
$(BUILDDIR)/tests/fuzz/fuzz-sha256: LDLIBS += -lcrypto
$(BUILDDIR)/tests/fuzz/fuzz-hmac-sha256: LDLIBS += -lcrypto
$(BUILDDIR)/tests/fuzz/fuzz-wire-*.o: tests/fuzz/wire.h
$(BUILDDIR)/tests/fuzz/fuzz-bolt12-*.o: tests/fuzz/bolt12.h

$(BUILDDIR)/tests/fuzz/fuzz-handle_onion_message: $(addprefix $(BUILDDIR)/,connectd/onion_message.o connectd/connectd_wiregen.o)
$(BUILDDIR)/tests/fuzz/fuzz-full_channel: $(addprefix $(BUILDDIR)/,channeld/full_channel.o channeld/commit_tx.o)
$(BUILDDIR)/tests/fuzz/fuzz-open_channel: $(addprefix $(BUILDDIR)/,hsmd/hsmd_wiregen.o openingd/common.o openingd/openingd_wiregen.o)

FUZZ_TARGETS_SRC := $(wildcard tests/fuzz/fuzz-*.c)
FUZZ_TARGETS_OBJS := $(FUZZ_TARGETS_SRC:%.c=$(BUILDDIR)/%.o)
FUZZ_TARGETS_BIN := $(FUZZ_TARGETS_OBJS:.o=)

$(FUZZ_TARGETS_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC) tests/fuzz/libfuzz.h
$(FUZZ_TARGETS_BIN): $(LIBFUZZ_OBJS) $(BUILDDIR)/libcommon.a

ALL_C_SOURCES += $(FUZZ_TARGETS_SRC) $(LIBFUZZ_SRC)
ALL_FUZZ_TARGETS += $(FUZZ_TARGETS_BIN)

# In non-fuzzing builds, these become normal tests.
ifneq ($(FUZZING),1)
check-units: $(FUZZ_TARGETS_BIN:%=fuzzunittest/%)
endif

obsclean::
	$(RM) tests/fuzz/*.o
