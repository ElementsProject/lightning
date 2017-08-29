check: lightningd/handshake-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_HANDSHAKE_TEST_SRC := $(wildcard lightningd/handshake/test/run-*.c)
LIGHTNINGD_HANDSHAKE_TEST_OBJS := $(LIGHTNINGD_HANDSHAKE_TEST_SRC:.c=.o)
LIGHTNINGD_HANDSHAKE_TEST_PROGRAMS := $(LIGHTNINGD_HANDSHAKE_TEST_OBJS:.o=)

LIGHTNINGD_HANDSHAKE_TEST_COMMON_OBJS :=	\
	common/cryptomsg.o			\
	common/daemon_conn.o			\
	common/dev_disconnect.o			\
	common/htlc_state.o			\
	common/msg_queue.o			\
	common/pseudorand.o			\
	common/status.o				\
	common/type_to_string.o			\
	common/utils.o

update-mocks: $(LIGHTNINGD_HANDSHAKE_TEST_SRC:%=update-mocks/%)

$(LIGHTNINGD_HANDSHAKE_TEST_PROGRAMS): $(LIGHTNINGD_HANDSHAKE_TEST_COMMON_OBJS) $(LIGHTNINGD_HANDSHAKE_GEN_SRC:.c=.o) $(BITCOIN_OBJS) $(WIRE_OBJS)

$(LIGHTNINGD_HANDSHAKE_TEST_OBJS): $(LIGHTNINGD_HANDSHAKE_HEADERS)

ALL_OBJS += $(LIGHTNINGD_HANDSHAKE_TEST_OBJS)
ALL_TEST_PROGRAMS += $(LIGHTNINGD_HANDSHAKE_TEST_PROGRAMS)

lightningd/handshake-tests: $(LIGHTNINGD_HANDSHAKE_TEST_PROGRAMS:%=unittest/%)

