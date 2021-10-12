# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(LIGHTNINGD_TEST_SRC)
ALL_TEST_PROGRAMS += $(LIGHTNINGD_TEST_PROGRAMS)

LIGHTNINGD_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bech32.o				\
	common/daemon_conn.o			\
	common/htlc_state.o			\
	common/json.o				\
	common/key_derive.o			\
	common/pseudorand.o			\
	common/random_select.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/setup.o				\
	common/utils.o				\
	common/utxo.o				\
	common/type_to_string.o			\
	common/permute_tx.o			\
	common/wireaddr.o			\

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIGHTNINGD_TEST_COMMON_OBJS)

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_SRC) $(LIGHTNINGD_SRC_NOHDR)

check-units: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)
