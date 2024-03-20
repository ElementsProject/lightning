WALLET_TEST_SRC := $(wildcard wallet/test/run-*.c)
WALLET_TEST_OBJS := $(WALLET_TEST_SRC:.c=.o)
WALLET_TEST_PROGRAMS := $(WALLET_TEST_OBJS:.o=)

ALL_C_SOURCES += $(WALLET_TEST_SRC)
ALL_TEST_PROGRAMS += $(WALLET_TEST_PROGRAMS)

WALLET_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/blockheight_states.o		\
	common/channel_type.o			\
	common/derive_basepoints.o		\
	common/features.o			\
	common/htlc_state.o			\
	common/hsm_capable.o			\
	common/htlc_wire.o			\
	common/fee_states.o			\
	common/memleak.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/key_derive.o			\
	common/psbt_keypath.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/timeout.o			\
	common/utils.o				\
	common/utxo.o				\
	common/wireaddr.o			\
	common/version.o			\
	wallet/db_sqlite3_sqlgen.o		\
	wire/towire.o				\
	wire/fromwire.o

$(WALLET_TEST_PROGRAMS): $(BITCOIN_OBJS) $(WALLET_TEST_COMMON_OBJS)
$(WALLET_TEST_OBJS): $(WALLET_HDRS) $(WALLET_SRC)

check-units: $(WALLET_TEST_PROGRAMS:%=unittest/%)
