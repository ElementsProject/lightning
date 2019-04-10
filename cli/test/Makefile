# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CLI_TEST_SRC := $(wildcard cli/test/run-*.c)
CLI_TEST_OBJS := $(CLI_TEST_SRC:.c=.o)
CLI_TEST_PROGRAMS := $(CLI_TEST_OBJS:.o=)

ALL_TEST_PROGRAMS += $(CLI_TEST_PROGRAMS)
ALL_OBJS += $(CLI_TEST_OBJS)

CLI_TEST_COMMON_OBJS :=				\
	common/configdir.o			\
	common/daemon_conn.o			\
	common/htlc_state.o			\
	common/json.o				\
	common/json_escaped.o			\
	common/pseudorand.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/utils.o				\
	common/type_to_string.o			\
	common/permute_tx.o

update-mocks: $(CLI_TEST_SRC:%=update-mocks/%)

$(CLI_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) $(CLI_TEST_COMMON_OBJS)

$(CLI_TEST_OBJS): $(LIGHTNING_CLI_HEADERS) $(LIGHTNING_CLI_SRC)

check: $(CLI_TEST_PROGRAMS:%=unittest/%)
