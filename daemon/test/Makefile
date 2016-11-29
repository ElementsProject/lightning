check: daemon-tests

# We run three different bitcoinds, for different types of tests.
# Provides limited paralellism.
daemon-test-0-%:
	NO_VALGRIND=$(NO_VALGRIND) VARIANT=0 daemon/test/test-$*
daemon-test-1-%:
	NO_VALGRIND=$(NO_VALGRIND) VARIANT=1 daemon/test/test-$*
daemon-test-2-%:
	NO_VALGRIND=$(NO_VALGRIND) VARIANT=2 daemon/test/test-$*

# These don't work in parallel, so chain the deps
daemon-test-0-steal: daemon-test-0-unilateral
daemon-test-0-unilateral: daemon-test-0-funding-timeout
daemon-test-0-funding-timeout: daemon-test-0-mutual-close-with-htlcs
daemon-test-0-mutual-close-with-htlcs: daemon-test-0-different-fees
daemon-test-0-different-fees: daemon-test-0-routing
daemon-test-0-routing: daemon-test-0-invoice
daemon-test-0-invoice: daemon-test-0-basic\ manual-commit
daemon-test-0-basic\ manual-commit: daemon-test-0-basic
daemon-test-0-basic: daemon-test-setup-0

daemon-test-2-steal\ --reconnect: daemon-test-2-unilateral\ --reconnect
daemon-test-2-unilateral\ --reconnect: daemon-test-2-funding-timeout\ --reconnect
daemon-test-2-funding-timeout\ --reconnect: daemon-test-2-mutual-close-with-htlcs\ --reconnect
daemon-test-2-mutual-close-with-htlcs\ --reconnect: daemon-test-2-different-fees\ --reconnect
daemon-test-2-different-fees\ --reconnect: daemon-test-2-routing\ --reconnect
daemon-test-2-routing\ --reconnect: daemon-test-2-invoice\ --reconnect
daemon-test-2-invoice\ --reconnect: daemon-test-2-basic\ manual-commit\ --reconnect
daemon-test-2-basic\ manual-commit\ --reconnect: daemon-test-2-basic\ --reconnect
daemon-test-2-basic\ --reconnect: daemon-test-setup-2

daemon-test-1-steal\ --restart: daemon-test-1-unilateral\ --restart
daemon-test-1-unilateral\ --restart: daemon-test-1-funding-timeout\ --restart
daemon-test-1-funding-timeout\ --restart: daemon-test-1-mutual-close-with-htlcs\ --restart
daemon-test-1-mutual-close-with-htlcs\ --restart: daemon-test-1-different-fees\ --restart
daemon-test-1-different-fees\ --restart: daemon-test-1-routing\ --restart
daemon-test-1-routing\ --restart: daemon-test-1-invoice\ --restart
daemon-test-1-invoice\ --restart: daemon-test-1-basic\ manual-commit\ --restart
daemon-test-1-basic\ manual-commit\ --restart: daemon-test-1-basic\ --restart
daemon-test-1-basic\ --restart: daemon-test-setup-1

# We shutdown first in case something is left over.
daemon-test-setup-%: daemon-all
	VARIANT=$* daemon/test/scripts/shutdown.sh 2>/dev/null || true
	VARIANT=$* daemon/test/scripts/setup.sh

daemon-test-shutdown-0: daemon-test-0-steal
	VARIANT=0 daemon/test/scripts/shutdown.sh
daemon-test-shutdown-1: daemon-test-1-steal\ --restart
	VARIANT=1 daemon/test/scripts/shutdown.sh
daemon-test-shutdown-2: daemon-test-2-steal\ --reconnect
	VARIANT=2 daemon/test/scripts/shutdown.sh

# Forms long dependency chains.
daemon-all-test: daemon-test-shutdown-0 daemon-test-shutdown-1 daemon-test-shutdown-2

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
DAEMON_TEST_SRC := $(wildcard daemon/test/run-*.c)
DAEMON_TEST_OBJS := $(DAEMON_TEST_SRC:.c=.o)
DAEMON_TEST_PROGRAMS := $(DAEMON_TEST_OBJS:.o=)

update-mocks: $(DAEMON_TEST_SRC:%=update-mocks/%)

$(DAEMON_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) libsecp256k1.a utils.o

$(DAEMON_TEST_OBJS): $(DAEMON_HEADERS) $(DAEMON_JSMN_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(DAEMON_GEN_HEADERS) $(CCAN_HEADERS)

daemon-unit-tests: $(DAEMON_TEST_PROGRAMS:%=unittest/%)

daemon-tests: daemon-unit-tests daemon-all-test

