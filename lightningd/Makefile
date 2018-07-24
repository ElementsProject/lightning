#! /usr/bin/make

# Designed to be run one level up
lightningd-wrongdir:
	$(MAKE) -C .. lightningd-all

LIGHTNINGD_PROGRAM := lightningd/lightningd

ALL_PROGRAMS += $(LIGHTNINGD_PROGRAM)

lightningd-all: $(LIGHTNINGD_PROGRAM)

default: lightningd-all

# Common source we use.
LIGHTNINGD_COMMON_OBJS :=			\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bip32.o				\
	common/bolt11.o				\
	common/channel_config.o			\
	common/configdir.o			\
	common/crypto_state.o			\
	common/daemon.o				\
	common/derive_basepoints.o		\
	common/features.o			\
	common/funding_tx.o			\
	common/gen_peer_status_wire.o		\
	common/gen_status_wire.o		\
	common/hash_u5.o			\
	common/htlc_state.o			\
	common/htlc_wire.o			\
	common/key_derive.o			\
	common/json.o				\
	common/json_escaped.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/sphinx.o				\
	common/status_wire.o			\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wallet_tx.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	common/withdraw_tx.o

LIGHTNINGD_SRC :=				\
	lightningd/bitcoind.c			\
	lightningd/chaintopology.c		\
	lightningd/channel.c			\
	lightningd/channel_control.c		\
	lightningd/closing_control.c		\
	lightningd/connect_control.c		\
	lightningd/gossip_control.c		\
	lightningd/gossip_msg.c			\
	lightningd/hsm_control.c		\
	lightningd/htlc_end.c			\
	lightningd/invoice.c			\
	lightningd/json.c			\
	lightningd/jsonrpc.c			\
	lightningd/lightningd.c			\
	lightningd/log.c			\
	lightningd/log_status.c			\
	lightningd/onchain_control.c		\
	lightningd/opening_control.c		\
	lightningd/options.c			\
	lightningd/param.c			\
	lightningd/pay.c			\
	lightningd/payalgo.c			\
	lightningd/peer_control.c		\
	lightningd/peer_htlcs.c			\
	lightningd/subd.c			\
	lightningd/watch.c

# Source files without corresponding headers
LIGHTNINGD_SRC_NOHDR :=				\
	lightningd/dev_ping.c			\
	lightningd/memdump.c

LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o) $(LIGHTNINGD_SRC_NOHDR:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_OBJS)

# We accumulate all lightningd/ headers in these three:
LIGHTNINGD_HEADERS_NOGEN =			\
	$(LIGHTNINGD_SRC:.c=.h)			\
	lightningd/channel_state.h			\
	lightningd/jsonrpc_errors.h

# Generated headers
LIGHTNINGD_HEADERS_GEN =			\
	lightningd/gen_channel_state_names.h

ALL_GEN_HEADERS += $(LIGHTNINGD_HEADERS_GEN)

# All together in one convenient var
LIGHTNINGD_HEADERS = $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) $(EXTERNAL_HEADERS) $(WIRE_HEADERS) $(BITCOIN_HEADERS) $(COMMON_HEADERS) $(WALLET_LIB_HEADERS) $(LIGHTNINGD_HSM_CLIENT_HEADERS)

$(LIGHTNINGD_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/gen_channel_state_names.h: lightningd/channel_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/channel_state.h > $@

check-source: $(LIGHTNINGD_SRC:%=check-src-include-order/%) $(LIGHTNINGD_SRC_NOHDR:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_HEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_SRC:%=bolt-check/%) $(LIGHTNINGD_HEADERS_NOGEN:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_SRC:%=check-whitespace/%) $(LIGHTNINGD_HEADERS_NOGEN:%=check-whitespace/%)

check-makefile: check-lightningd-makefile
check-lightningd-makefile:
	@for f in lightningd/*.h lightningd/*/*.h; do if ! echo $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) "" | grep -q "$$f "; then echo $$f not mentioned in LIGHTNINGD_HEADERS_NOGEN or LIGHTNINGD_HEADERS_GEN >&2; exit 1; fi; done

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(LIGHTNINGD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS) $(LIGHTNINGD_HANDSHAKE_CONTROL_OBJS) $(LIGHTNINGD_GOSSIP_CONTROL_OBJS) $(LIGHTNINGD_OPENING_CONTROL_OBJS) $(LIGHTNINGD_CHANNEL_CONTROL_OBJS) $(LIGHTNINGD_CLOSING_CONTROL_OBJS) $(LIGHTNINGD_ONCHAIN_CONTROL_OBJS) $(WALLET_LIB_OBJS) $(LIGHTNINGD_CONNECT_CONTROL_OBJS) 

clean: lightningd-clean

lightningd-clean:
	$(RM) $(LIGHTNINGD_OBJS) $(LIGHTNINGD_JSMN_OBJS) $(LIGHTNINGD_PROGRAM) lightningd/gen*

include lightningd/test/Makefile
