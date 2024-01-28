COMMON_SRC_NOGEN :=				\
	common/addr.c				\
	common/amount.c				\
	common/autodata.c			\
	common/base32.c				\
	common/base64.c				\
	common/bech32.c				\
	common/bech32_util.c			\
	common/bigsize.c			\
	common/billboard.c			\
	common/bip32.c				\
	common/blindedpath.c			\
	common/blindedpay.c			\
	common/blinding.c			\
	common/blockheight_states.c		\
	common/bolt11.c				\
	common/bolt11_json.c			\
	common/bolt12.c				\
	common/bolt12_merkle.c			\
	common/channel_config.c			\
	common/channel_id.c			\
	common/channel_type.c			\
	common/close_tx.c			\
	common/codex32.c			\
	common/coin_mvt.c			\
	common/configdir.c			\
	common/configvar.c			\
	common/cryptomsg.c			\
	common/daemon.c				\
	common/daemon_conn.c			\
	common/decode_array.c			\
	common/deprecation.c			\
	common/derive_basepoints.c		\
	common/descriptor_checksum.c		\
	common/dev_disconnect.c			\
	common/dijkstra.c			\
	common/ecdh_hsmd.c			\
	common/features.c			\
	common/fee_states.c			\
	common/fp16.c				\
	common/gossip_store.c			\
	common/gossmap.c			\
	common/gossmods_listpeerchannels.c	\
	common/hash_u5.c			\
	common/hmac.c				\
	common/hsm_encryption.c			\
	common/htlc_state.c			\
	common/htlc_trim.c			\
	common/htlc_tx.c			\
	common/htlc_wire.c			\
	common/interactivetx.c			\
	common/initial_channel.c		\
	common/initial_commit_tx.c		\
	common/invoice_path_id.c		\
	common/iso4217.c			\
	common/json_channel_type.c		\
	common/json_filter.c			\
	common/json_param.c			\
	common/json_parse.c			\
	common/json_parse_simple.c		\
	common/json_stream.c			\
	common/key_derive.c			\
	common/keyset.c				\
	common/lease_rates.c			\
	common/memleak.c			\
	common/msg_queue.c			\
	common/node_id.c			\
	common/onion_decode.c			\
	common/onion_encode.c			\
	common/onionreply.c			\
	common/onion_message_parse.c		\
	common/peer_billboard.c			\
	common/peer_failed.c			\
	common/peer_io.c			\
	common/penalty_base.c			\
	common/per_peer_state.c			\
	common/permute_tx.c			\
	common/ping.c				\
	common/private_channel_announcement.c	\
	common/psbt_internal.c			\
	common/psbt_keypath.c			\
	common/psbt_open.c			\
	common/pseudorand.c			\
	common/random_select.c			\
	common/read_peer_msg.c			\
	common/route.c				\
	common/setup.c				\
	common/shutdown_scriptpubkey.c		\
	common/sphinx.c				\
	common/status.c				\
	common/status_levels.c			\
	common/status_wire.c			\
	common/subdaemon.c			\
	common/timeout.c			\
	common/trace.c				\
	common/tx_roles.c			\
	common/type_to_string.c			\
	common/utils.c				\
	common/utxo.c				\
	common/version.c			\
	common/wallet.c				\
	common/wireaddr.c			\
	common/wire_error.c


COMMON_SRC_GEN := common/status_wiregen.c common/peer_status_wiregen.c common/scb_wiregen.c

COMMON_HEADERS_NOGEN := $(COMMON_SRC_NOGEN:.c=.h)	\
	common/closing_fee.h				\
	common/crypto_state.h				\
	common/ecdh.h					\
	common/errcode.h				\
	common/gossip_constants.h			\
	common/hsm_version.h				\
	common/htlc.h					\
	common/json_command.h				\
	common/jsonrpc_errors.h				\
	common/overflows.h

COMMON_HEADERS_GEN := common/htlc_state_names_gen.h common/status_wiregen.h common/peer_status_wiregen.h common/scb_wiregen.h

COMMON_HEADERS := $(COMMON_HEADERS_GEN) $(COMMON_HEADERS_NOGEN)
COMMON_SRC := $(COMMON_SRC_NOGEN) $(COMMON_SRC_GEN)

COMMON_OBJS := $(COMMON_SRC:.c=.o)

common/scb_wiregen.h_args := -s
common/scb_wiregen.c_args := -s

# Check that all h and c files are in the Makefile!
check-common-files:
	@$(call VERBOSE, "MISSING-SRC common", [ "$(filter-out $(COMMON_SRC), $(wildcard common/*.c))" = "" ])
	@$(call VERBOSE, "MISSING-HEADERS common", [ "$(filter-out $(COMMON_HEADERS) $(COMMON_SRC:.c=.h), $(wildcard common/*.h))" = "" ])

check-source: check-common-files

# Common objects depends on bitcoin/ external/ and ccan
$(COMMON_OBJS): $(CCAN_HEADERS) $(BITCOIN_HEADERS) $(EXTERNAL_HEADERS) $(COMMON_HEADERS_GEN)

# Only common/version.c can include this header.
common/version.o: version_gen.h

ALL_C_HEADERS += $(COMMON_HEADERS)
ALL_C_SOURCES += $(COMMON_SRC)

common/htlc_state_names_gen.h: common/htlc_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr common/htlc_state.h > $@

common/gossip_store.o: gossipd/gossip_store_wiregen.h

check-source-bolt: $(COMMON_SRC_NOGEN:%=bolt-check/%) $(COMMON_HEADERS:%=bolt-check/%)
check-whitespace: $(COMMON_SRC_NOGEN:%=check-whitespace/%) $(COMMON_HEADERS:%=check-whitespace/%)

clean: common-clean

common-clean:
	$(RM) common/gen*

include common/test/Makefile
