WALLET_TEST_SRC := $(wildcard wallet/test/run-*.c)
WALLET_TEST_OBJS := $(WALLET_TEST_SRC:.c=.o)
WALLET_TEST_PROGRAMS := $(WALLET_TEST_OBJS:.o=)

ALL_C_SOURCES += $(WALLET_TEST_SRC)
ALL_TEST_PROGRAMS += $(WALLET_TEST_PROGRAMS)

$(WALLET_TEST_PROGRAMS): wallet/db_sqlite3_sqlgen.o libcommon.a
$(WALLET_TEST_OBJS): $(WALLET_HDRS) $(WALLET_SRC) wallet/test/Makefile

check-units: $(WALLET_TEST_PROGRAMS:%=unittest/%)
