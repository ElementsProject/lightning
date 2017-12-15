# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

ALL_TEST_PROGRAMS += $(LIGHTNINGD_TEST_PROGRAMS)
ALL_OBJS += $(LIGHTNINGD_TEST_OBJS)

LIGHTNINGD_TEST_COMMON_OBJS :=			\
	common/daemon_conn.o			\
	common/htlc_state.o			\
	common/pseudorand.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/utils.o				\
	common/type_to_string.o			\
	common/permute_tx.o

update-mocks: $(LIGHTNINGD_TEST_SRC:%=update-mocks/%)

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) $(LIGHTNINGD_TEST_COMMON_OBJS)

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_SRC)

check: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)
