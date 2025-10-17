BITCOIN_TEST_SRC := $(wildcard bitcoin/test/run-*.c)
BITCOIN_TEST_OBJS := $(BITCOIN_TEST_SRC:.c=.o)
BITCOIN_TEST_PROGRAMS := $(BITCOIN_TEST_OBJS:.o=)

$(BITCOIN_TEST_PROGRAMS): bitcoin/chainparams.o libcommon.a
$(BITCOIN_TEST_OBJS): $(BITCOIN_HEADERS) $(BITCOIN_SRC) bitcoin/test/Makefile

ALL_TEST_PROGRAMS += $(BITCOIN_TEST_PROGRAMS)
ALL_C_SOURCES += $(BITCOIN_TEST_PROGRAMS:=.c)

# This needs to know what level of optimization we're using.
bitcoin/test/run-secret_eq_consttime.o: CFLAGS += -DCOPTFLAGS="\"${COPTFLAGS}\""

check-units: $(BITCOIN_TEST_PROGRAMS:%=unittest/%)
