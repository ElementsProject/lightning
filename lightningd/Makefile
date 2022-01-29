#! /usr/bin/make

LIGHTNINGD_SRC :=				\
	lightningd/bitcoind.c			\
	lightningd/chaintopology.c		\
	lightningd/channel.c			\
	lightningd/channel_control.c		\
	lightningd/closing_control.c		\
	lightningd/coin_mvts.c			\
	lightningd/dual_open_control.c		\
	lightningd/connect_control.c		\
	lightningd/onion_message.c		\
	lightningd/gossip_control.c		\
	lightningd/hsm_control.c		\
	lightningd/htlc_end.c			\
	lightningd/htlc_set.c			\
	lightningd/invoice.c			\
	lightningd/io_loop_with_timers.c	\
	lightningd/json.c			\
	lightningd/jsonrpc.c			\
	lightningd/lightningd.c			\
	lightningd/log.c			\
	lightningd/log_status.c			\
	lightningd/memdump.c			\
	lightningd/notification.c		\
	lightningd/onchain_control.c		\
	lightningd/opening_common.c		\
	lightningd/opening_control.c		\
	lightningd/options.c			\
	lightningd/pay.c			\
	lightningd/peer_control.c		\
	lightningd/peer_fd.c			\
	lightningd/peer_htlcs.c			\
	lightningd/plugin.c			\
	lightningd/plugin_control.c		\
	lightningd/plugin_hook.c		\
	lightningd/routehint.c			\
	lightningd/subd.c			\
	lightningd/watch.c


LIGHTNINGD_SRC_NOHDR :=				\
	lightningd/datastore.c			\
	lightningd/ping.c			\
	lightningd/offer.c			\
	lightningd/signmessage.c

LIGHTNINGD_HEADERS :=				\
	$(LIGHTNINGD_SRC:.c=.h)			\
	lightningd/channel_state.h		\
	lightningd/channel_state_names_gen.h


LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o) $(LIGHTNINGD_SRC_NOHDR:.c=.o)
$(LIGHTNINGD_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_CONTROL_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(LIGHTNINGD_SRC) $(LIGHTNINGD_SRC_NOHDR)
ALL_C_HEADERS += $(LIGHTNINGD_HEADERS)
ALL_PROGRAMS += lightningd/lightningd

# Common source we use.
LIGHTNINGD_COMMON_OBJS :=			\
	common/addr.o				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/base64.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bip32.o				\
	common/blindedpath.o			\
	common/blinding.o			\
	common/blockheight_states.o		\
	common/bolt11.o				\
	common/bolt11_json.o			\
	common/bolt12.o				\
	common/bolt12_merkle.o			\
	common/channel_config.o			\
	common/channel_id.o			\
	common/channel_type.o			\
	common/coin_mvt.o			\
	common/configdir.o			\
	common/daemon.o				\
	common/derive_basepoints.o		\
	common/ecdh_hsmd.o			\
	common/features.o			\
	common/fee_states.o			\
	common/peer_status_wiregen.o		\
	common/status_levels.o			\
	common/status_wiregen.o			\
	common/gossip_rcvd_filter.o		\
	common/hash_u5.o			\
	common/hmac.o				\
	common/hsm_encryption.o			\
	common/htlc_state.o			\
	common/htlc_trim.o			\
	common/htlc_wire.o			\
	common/key_derive.o			\
	common/keyset.o				\
	common/json.o				\
	common/json_helpers.o			\
	common/json_stream.o			\
	common/json_tok.o			\
	common/lease_rates.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onion.o				\
	common/onionreply.o			\
	common/param.o				\
	common/penalty_base.o			\
	common/per_peer_state.o			\
	common/permute_tx.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/random_select.o			\
	common/setup.o				\
	common/shutdown_scriptpubkey.o		\
	common/sphinx.o				\
	common/status_wire.o			\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wallet.o				\
	common/wire_error.o			\
	common/wireaddr.o			\

include wallet/Makefile

# All together in one convenient var
LIGHTNINGD_HEADERS = $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) $(WALLET_HDRS)

$(LIGHTNINGD_OBJS): $(LIGHTNINGD_HEADERS)

# Only the plugin component needs to depend on this header.
lightningd/plugin.o: plugins/list_of_builtin_plugins_gen.h

lightningd/channel_state_names_gen.h: lightningd/channel_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/channel_state.h > $@

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(WALLET_OBJS) $(LIGHTNINGD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(LIGHTNINGD_CONTROL_OBJS) $(HSMD_CLIENT_OBJS)

include lightningd/test/Makefile
