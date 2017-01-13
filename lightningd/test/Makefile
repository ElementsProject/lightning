# FIXME: check doesn't cover lightningd-blackbox-tests, since they
# can't run in parallel with daemon blackbox tests.

check: lightningd/tests #lightningd-blackbox-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

update-mocks: $(LIGHTNINGD_TEST_SRC:%=update-mocks/%)

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) $(LIGHTNINGD_HANDSHAKE_GEN_SRC:.c=.o) utils.o libsecp256k1.a libsodium.a

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/tests: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)

# So far, only basic test.
lightningd-test-0-basic: lightningd-test-setup-0

lightningd-test-0-%:
	NO_VALGRIND=$(NO_VALGRIND) VARIANT=0 lightningd/test/test-$*

# We shutdown first in case something is left over.
lightningd-test-setup-%: lightningd-all daemon/lightning-cli
	VARIANT=$* daemon/test/scripts/shutdown.sh 2>/dev/null || true
	VARIANT=$* daemon/test/scripts/setup.sh

lightningd-test-shutdown-0: lightningd-test-0-basic
	VARIANT=0 daemon/test/scripts/shutdown.sh
lightningd-test-shutdown-1: lightningd-test-1-basic\ --restart
	VARIANT=1 daemon/test/scripts/shutdown.sh
lightningd-test-shutdown-2: lightningd-test-2-basic\ --reconnect
	VARIANT=2 daemon/test/scripts/shutdown.sh

lightningd-blackbox-tests: lightningd-test-shutdown-0 #lightningd-test-shutdown-1 lightningd-test-shutdown-2
