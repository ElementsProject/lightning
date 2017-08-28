# Included for one dir up.

# Note that these actually #include everything they need, except ccan/.
# That allows for unit testing of statics, and special effects.

BITCOIN_TEST_SRC := $(wildcard bitcoin/test/run-*.c)
BITCOIN_TEST_OBJS := $(BITCOIN_TEST_SRC:.c=.o)
BITCOIN_TEST_PROGRAMS := $(BITCOIN_TEST_OBJS:.o=)

$(BITCOIN_TEST_PROGRAMS): $(CCAN_OBJS)

$(BITCOIN_TEST_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(BITCOIN_SRC)

check: bitcoin-tests

check-source-bolt: $(BITCOIN_SRC:%=bolt-check/%) $(BITCOIN_HEADERS:%=bolt-check/%)

check-makefile: check-bitcoin-makefile

check-bitcoin-makefile:
	@if [ "`echo bitcoin/*.h`" != "$(BITCOIN_HEADERS)" ]; then echo BITCOIN_HEADERS incorrect; exit 1; fi

check-whitespace: $(BITCOIN_SRC:%=check-whitespace/%) $(BITCOIN_HEADERS:%=check-whitespace/%) check-whitespace/bitcoin/Makefile

bitcoin-tests: $(BITCOIN_TEST_PROGRAMS:%=unittest/%)

