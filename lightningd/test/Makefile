# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(LIGHTNINGD_TEST_SRC)
ALL_TEST_PROGRAMS += $(LIGHTNINGD_TEST_PROGRAMS)

# run-find_my_abspath.c includes lightningd.c, which includes header_versions_gen.h
lightningd/test/run-find_my_abspath.o: header_versions_gen.h

LIGHTNINGD_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bech32.o				\
	common/daemon_conn.o			\
	common/htlc_state.o			\
	common/htlc_wire.o			\
	common/json_parse_simple.o		\
	common/key_derive.o			\
	common/pseudorand.o			\
	common/random_select.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/onionreply.o			\
	common/setup.o				\
	common/utils.o				\
	common/utxo.o				\
	common/permute_tx.o			\
	common/wireaddr.o			\

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIGHTNINGD_TEST_COMMON_OBJS) $(WIRE_BOLT12_OBJS)

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HDRS) $(LIGHTNINGD_SRC) $(LIGHTNINGD_SRC_NOHDR)

check-units: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)
