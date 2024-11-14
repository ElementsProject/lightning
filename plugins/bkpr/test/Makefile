BOOKKEEPER_TEST_SRC := $(wildcard plugins/bkpr/test/run-*.c)
BOOKKEEPER_TEST_OBJS := $(BOOKKEEPER_TEST_SRC:.c=.o)
BOOKKEEPER_TEST_PROGRAMS := $(BOOKKEEPER_TEST_OBJS:.o=)

ALL_C_SOURCES += $(BOOKKEEPER_TEST_SRC)
ALL_TEST_PROGRAMS += $(BOOKKEEPER_TEST_PROGRAMS)

BOOKKEEPER_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/blockheight_states.o		\
	common/channel_type.o			\
	common/coin_mvt.o			\
	common/features.o			\
	common/json_stream.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/node_id.o			\
	common/setup.o				\
	common/trace.o				\
	common/timeout.o			\
	common/utils.o				\
	common/version.o			\
	db/bindings.o				\
	db/db_sqlite3.o				\
	db/exec.o				\
	db/utils.o				\
	plugins/bkpr/account.o			\
	plugins/bkpr/db_sqlite3_sqlgen.o	\
	plugins/bkpr/recorder.o

$(BOOKKEEPER_TEST_PROGRAMS): $(BITCOIN_OBJS) $(BOOKKEEPER_TEST_COMMON_OBJS)
$(BOOKKEEPER_TEST_OBJS): $(BOOKKEEPER_HEADER) $(BOOKKEEPER_SRC) $(BOOKKEEPER_TEST_COMMON_OBJS)

check-units: $(BOOKKEEPER_TEST_PROGRAMS:%=unittest/%)
