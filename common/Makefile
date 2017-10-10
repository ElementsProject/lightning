COMMON_SRC :=					\
	common/bip32.c				\
	common/channel_config.c			\
	common/close_tx.c			\
	common/configdir.c			\
	common/crypto_state.c			\
	common/crypto_sync.c			\
	common/cryptomsg.c			\
	common/daemon_conn.c			\
	common/debug.c				\
	common/derive_basepoints.c		\
	common/dev_disconnect.c			\
	common/funding_tx.c			\
	common/htlc_state.c			\
	common/htlc_tx.c			\
	common/htlc_wire.c			\
	common/initial_channel.c		\
	common/initial_commit_tx.c		\
	common/io_debug.c			\
	common/json.c				\
	common/key_derive.c			\
	common/keyset.c				\
	common/msg_queue.c			\
	common/peer_failed.c			\
	common/permute_tx.c			\
	common/ping.c				\
	common/pseudorand.c			\
	common/sphinx.c				\
	common/status.c				\
	common/timeout.c			\
	common/type_to_string.c			\
	common/utils.c				\
	common/utxo.c				\
	common/version.c			\
	common/wire_error.c			\
	common/withdraw_tx.c

COMMON_HEADERS_NOGEN := $(COMMON_SRC:.c=.h) common/overflows.h common/htlc.h
COMMON_HEADERS_GEN := common/gen_htlc_state_names.h

COMMON_HEADERS := $(COMMON_HEADERS_GEN) $(COMMON_HEADERS_NOGEN)
COMMON_OBJS := $(COMMON_SRC:.c=.o)

# Common objects depends on bitcoin/ external/ and ccan
$(COMMON_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(EXTERNAL_HEADERS) $(COMMON_HEADERS_GEN)

ALL_GEN_HEADERS += $(COMMON_HEADERS_GEN)
ALL_OBJS += $(COMMON_OBJS)

common/gen_htlc_state_names.h: common/htlc_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr common/htlc_state.h > $@

check-makefile: check-common-makefile

check-common-makefile:
	@if [ x"`LC_ALL=C ls common/*.h | grep -v ^common/gen_`" != x"`echo $(COMMON_HEADERS_NOGEN) | tr ' ' '\n' | LC_ALL=C sort`" ]; then echo COMMON_HEADERS_NOGEN incorrect; exit 1; fi

check-source-bolt: $(COMMON_SRC:%=bolt-check/%) $(COMMON_HEADERS:%=bolt-check/%)
check-whitespace: $(COMMON_SRC:%=check-whitespace/%) $(COMMON_HEADERS:%=check-whitespace/%)

check-source: $(COMMON_SRC:%=check-src-include-order/%)			\
	$(COMMON_HEADERS_NOGEN:%=check-hdr-include-order/%)

include common/test/Makefile
