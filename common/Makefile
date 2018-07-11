COMMON_SRC_NOGEN :=				\
	common/base32.c				\
	common/bech32.c				\
	common/bech32_util.c			\
	common/bip32.c				\
	common/bolt11.c				\
	common/channel_config.c			\
	common/close_tx.c			\
	common/configdir.c			\
	common/crypto_state.c			\
	common/crypto_sync.c			\
	common/cryptomsg.c			\
	common/daemon.c				\
	common/daemon_conn.c			\
	common/decode_short_channel_ids.c	\
	common/derive_basepoints.c		\
	common/dev_disconnect.c			\
	common/features.c			\
	common/funding_tx.c			\
	common/hash_u5.c			\
	common/htlc_state.c			\
	common/htlc_tx.c			\
	common/htlc_wire.c			\
	common/initial_channel.c		\
	common/initial_commit_tx.c		\
	common/json.c				\
	common/json_escaped.c			\
	common/key_derive.c			\
	common/keyset.c				\
	common/memleak.c			\
	common/msg_queue.c			\
	common/peer_billboard.c			\
	common/peer_failed.c			\
	common/permute_tx.c			\
	common/ping.c				\
	common/pseudorand.c			\
	common/read_peer_msg.c			\
	common/socket_close.c			\
	common/sphinx.c				\
	common/status.c				\
	common/status_wire.c			\
	common/subdaemon.c			\
	common/timeout.c			\
	common/type_to_string.c			\
	common/utils.c				\
	common/utxo.c				\
	common/version.c			\
	common/wallet_tx.c			\
	common/wireaddr.c			\
	common/wire_error.c			\
	common/withdraw_tx.c

COMMON_SRC_GEN := common/gen_status_wire.c common/gen_peer_status_wire.c

COMMON_HEADERS_NOGEN := $(COMMON_SRC_NOGEN:.c=.h) common/overflows.h common/htlc.h common/status_levels.h
COMMON_HEADERS_GEN := common/gen_htlc_state_names.h common/gen_status_wire.h common/gen_peer_status_wire.h

COMMON_HEADERS := $(COMMON_HEADERS_GEN) $(COMMON_HEADERS_NOGEN)
COMMON_SRC := $(COMMON_SRC_NOGEN) $(COMMON_SRC_GEN)

COMMON_OBJS := $(COMMON_SRC:.c=.o)

# Common objects depends on bitcoin/ external/ and ccan
$(COMMON_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(EXTERNAL_HEADERS) $(COMMON_HEADERS_GEN)

ALL_GEN_HEADERS += $(COMMON_HEADERS_GEN)
ALL_OBJS += $(COMMON_OBJS)

common/gen_htlc_state_names.h: common/htlc_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr common/htlc_state.h > $@

common/gen_status_wire.h: $(WIRE_GEN) common/status_wire.csv
	$(WIRE_GEN) --header $@ status < common/status_wire.csv > $@

common/gen_status_wire.c: $(WIRE_GEN) common/status_wire.csv
	$(WIRE_GEN) ${@:.c=.h} status < common/status_wire.csv > $@

common/gen_peer_status_wire.h: $(WIRE_GEN) common/peer_status_wire.csv
	$(WIRE_GEN) --header $@ peer_status < common/peer_status_wire.csv > $@

common/gen_peer_status_wire.c: $(WIRE_GEN) common/peer_status_wire.csv
	$(WIRE_GEN) ${@:.c=.h} peer_status < common/peer_status_wire.csv > $@

check-makefile: check-common-makefile

check-common-makefile:
	if [ x"`LC_ALL=C ls common/*.h | grep -v ^common/gen_`" != x"`echo $(COMMON_HEADERS_NOGEN) | tr ' ' '\n' | LC_ALL=C sort`" ]; then echo COMMON_HEADERS_NOGEN incorrect; exit 1; fi

check-source-bolt: $(COMMON_SRC_NOGEN:%=bolt-check/%) $(COMMON_HEADERS:%=bolt-check/%)
check-whitespace: $(COMMON_SRC_NOGEN:%=check-whitespace/%) $(COMMON_HEADERS:%=check-whitespace/%)

check-source: $(COMMON_SRC_NOGEN:%=check-src-include-order/%)		\
	$(COMMON_HEADERS_NOGEN:%=check-hdr-include-order/%)

clean: common-clean

common-clean:
	$(RM) common/gen*

include common/test/Makefile
