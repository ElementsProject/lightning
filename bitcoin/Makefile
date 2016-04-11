# Included for one dir up.

# Note that these actually #include everything they need, except ccan/.
# That allows for unit testing of statics, and special effects.

BITCOIN_TEST_SRC := $(wildcard bitcoin/test/run-*.c)
BITCOIN_TEST_OBJS := $(BITCOIN_TEST_SRC:.c=.o)
BITCOIN_TEST_PROGRAMS := $(BITCOIN_TEST_OBJS:.o=)

$(BITCOIN_TEST_PROGRAMS): $(CCAN_OBJS)

$(BITCOIN_TEST_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(BITCOIN_SRC)

VALGRIND=valgrind -q --error-exitcode=99
VALGRIND_TEST_ARGS = --track-origins=yes --leak-check=full --show-reachable=yes

bitcoin-tests: $(BITCOIN_TEST_PROGRAMS)
	set -e; for f in $(BITCOIN_TEST_PROGRAMS); do $(VALGRIND) $(VALGRIND_TEST_ARGS) $$f; done
