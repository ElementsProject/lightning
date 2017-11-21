# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CHANNELD_TEST_SRC := $(wildcard channeld/test/run-*.c)
CHANNELD_TEST_OBJS := $(CHANNELD_TEST_SRC:.c=.o)
CHANNELD_TEST_PROGRAMS := $(CHANNELD_TEST_OBJS:.o=)

ALL_TEST_PROGRAMS += $(CHANNELD_TEST_PROGRAMS)
ALL_OBJS += $(CHANNELD_TEST_OBJS)

CHANNELD_TEST_COMMON_OBJS :=			\
	common/daemon_conn.o			\
	common/htlc_state.o			\
	common/pseudorand.o			\
	common/msg_queue.o			\
	common/utils.o				\
	common/type_to_string.o			\
	common/permute_tx.o

update-mocks: $(CHANNELD_TEST_SRC:%=update-mocks/%)

$(CHANNELD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) $(CHANNELD_TEST_COMMON_OBJS)

$(CHANNELD_TEST_OBJS): $(LIGHTNING_CHANNELD_HEADERS) $(LIGHTNING_CHANNELD_SRC)

check: $(CHANNELD_TEST_PROGRAMS:%=unittest/%)
