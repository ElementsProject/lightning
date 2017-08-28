#! /usr/bin/make

# Designed to be run one level up
lightningd-wrongdir:
	$(MAKE) -C .. lightningd-all

LIGHTNINGD_BINS := lightningd/lightningd lightningd/lightningd_hsm lightningd/lightningd_handshake lightningd/lightningd_gossip lightningd/lightningd_opening lightningd/lightningd_channel lightningd/lightningd_closing lightningd/lightningd_onchain

lightningd-all: $(LIGHTNINGD_BINS)

default: lightningd-all

# Common source we use.
LIGHTNINGD_COMMON_OBJS :=			\
	common/configdir.o			\
	common/derive_basepoints.o		\
	common/funding_tx.o			\
	common/htlc_state.o			\
	common/json.o				\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o			\
	common/withdraw_tx.o

# FIXME: put in a library so we don't link all of them.
LIGHTNINGD_LIB_SRC :=				\
	lightningd/bip32.c			\
	lightningd/channel_config.c		\
	lightningd/cryptomsg.c			\
	lightningd/crypto_sync.c		\
	lightningd/debug.c			\
	lightningd/daemon_conn.c		\
	lightningd/dev_disconnect.c		\
	lightningd/gossip_msg.c			\
	lightningd/htlc_wire.c			\
	lightningd/key_derive.c			\
	lightningd/keyset.c			\
	lightningd/msg_queue.c			\
	lightningd/peer_failed.c		\
	lightningd/ping.c			\
	lightningd/sphinx.c			\
	lightningd/status.c			\
	lightningd/utxo.c

LIGHTNINGD_LIB_OBJS := $(LIGHTNINGD_LIB_SRC:.c=.o)
LIGHTNINGD_LIB_HEADERS := $(LIGHTNINGD_LIB_SRC:.c=.h)

LIGHTNINGD_SRC :=				\
	lightningd/bitcoind.c			\
	lightningd/build_utxos.c		\
	lightningd/chaintopology.c		\
	lightningd/dns.c			\
	lightningd/gossip_control.c		\
	lightningd/hsm_control.c		\
	lightningd/htlc_end.c			\
	lightningd/invoice.c			\
	lightningd/jsonrpc.c			\
	lightningd/lightningd.c			\
	lightningd/log.c			\
	lightningd/netaddr.c			\
	lightningd/new_connection.c		\
	lightningd/opt_time.c			\
	lightningd/options.c			\
	lightningd/pay.c			\
	lightningd/peer_control.c		\
	lightningd/peer_htlcs.c			\
	lightningd/subd.c			\
	lightningd/watch.c

# Source files without corresponding headers
LIGHTNINGD_SRC_NOHDR :=				\
	lightningd/dev_ping.c			\

LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o) $(LIGHTNINGD_SRC_NOHDR:.c=.o)

LIGHTNINGD_JSMN_OBJS := daemon/jsmn.o
LIGHTNINGD_JSMN_HEADERS := daemon/jsmn/jsmn.h

# We accumulate all lightningd/ headers in these three:
LIGHTNINGD_HEADERS_NOGEN =			\
	$(LIGHTNINGD_SRC:.c=.h)			\
	lightningd/peer_state.h			\
	$(LIGHTNINGD_LIB_HEADERS)		\
	$(WIRE_HEADERS)				\
	$(BITCOIN_HEADERS)			\
	$(COMMON_HEADERS_NOGEN)			\
	$(WALLET_LIB_HEADERS)

# Generated headers
LIGHTNINGD_HEADERS_GEN =			\
	lightningd/gen_peer_state_names.h	\
	lightningd/gen_peer_state_names.h	\
	$(COMMON_HEADERS_GEN)			\
	$(WIRE_GEN_HEADERS)			\
	$(GEN_HEADERS)

# Headers we don't directly own (ie. don't check them)
LIGHTNINGD_EXTERNAL_HEADERS =			\
	$(LIGHTNINGD_JSMN_HEADERS)		\
	$(CCAN_HEADERS)				\
	$(LIBBASE58_HEADERS)			\
	$(LIBSODIUM_HEADERS)

# All together in one convenient var
LIGHTNINGD_HEADERS = $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) $(LIGHTNINGD_EXTERNAL_HEADERS)

# These included makefiles add their headers to the LIGHTNINGD_HEADERS
# variable so the include must preceed any actual use of the variable.
include lightningd/hsm/Makefile
include lightningd/handshake/Makefile
include lightningd/gossip/Makefile
include lightningd/opening/Makefile
include lightningd/channel/Makefile
include lightningd/closing/Makefile
include lightningd/onchain/Makefile

$(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS): $(LIGHTNINGD_HEADERS) 

lightningd/gen_peer_state_names.h: lightningd/peer_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/peer_state.h > $@

check-source: $(LIGHTNINGD_SRC:%=check-src-include-order/%) $(LIGHTNINGD_SRC_NOHDR:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_LIB_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_CLI_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_HEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_SRC:%=bolt-check/%) $(LIGHTNINGD_LIB_SRC:%=bolt-check/%) $(LIGHTNINGD_HEADERS_NOGEN:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_SRC:%=check-whitespace/%) $(LIGHTNINGD_HEADERS_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_LIB_SRC:%=check-whitespace/%) $(LIGHTNINGD_LIB_HEADERS:%=check-whitespace/%)

check-makefile: check-lightningd-makefile
check-lightningd-makefile:
	@for f in lightningd/*.h lightningd/*/*.h; do if ! echo $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) "" | grep -q "$$f "; then echo $$f not mentioned in LIGHTNINGD_HEADERS_NOGEN or LIGHTNINGD_HEADERS_GEN >&2; exit 1; fi; done

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_COMMON_OBJS) $(LIGHTNINGD_JSMN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_HSM_CONTROL_OBJS) $(LIGHTNINGD_HANDSHAKE_CONTROL_OBJS) $(LIGHTNINGD_GOSSIP_CONTROL_OBJS) $(LIBBASE58_OBJS) $(LIGHTNINGD_OPENING_CONTROL_OBJS) $(LIGHTNINGD_CHANNEL_CONTROL_OBJS) $(LIGHTNINGD_CLOSING_CONTROL_OBJS) $(LIGHTNINGD_ONCHAIN_CONTROL_OBJS) $(WALLET_LIB_OBJS) libsecp256k1.a libsodium.a libwallycore.a

clean: lightningd-clean

lightningd-clean:
	$(RM) $(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_JSMN_OBJS) $(LIGHTNINGD_BINS)

include lightningd/test/Makefile
