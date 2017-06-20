#! /usr/bin/make

# Designed to be run one level up
lightningd-wrongdir:
	$(MAKE) -C .. lightningd-all

lightningd-all: lightningd/lightningd lightningd/lightningd_hsm lightningd/lightningd_handshake lightningd/lightningd_gossip lightningd/lightningd_opening lightningd/lightningd_channel

default: lightningd-all

LIGHTNINGD_OLD_SRC :=				\
	daemon/bitcoind.c			\
	daemon/broadcast.c			\
	daemon/chaintopology.c			\
	daemon/configdir.c			\
	daemon/dns.c				\
	daemon/invoice.c			\
	daemon/json.c				\
	daemon/jsonrpc.c			\
	daemon/log.c				\
	daemon/netaddr.c			\
	daemon/options.c			\
	daemon/opt_time.c			\
	daemon/pseudorand.c			\
	daemon/routing.c			\
	daemon/watch.c
LIGHTNINGD_OLD_OBJS := $(LIGHTNINGD_OLD_SRC:.c=.o)
LIGHTNINGD_OLD_HEADERS := $(LIGHTNINGD_OLD_SRC:.c=.h)

LIGHTNINGD_OLD_LIB_SRC :=			\
	daemon/htlc_state.c			\
	daemon/pseudorand.c			\
	daemon/timeout.c
LIGHTNINGD_OLD_LIB_OBJS := $(LIGHTNINGD_OLD_LIB_SRC:.c=.o)
LIGHTNINGD_OLD_LIB_HEADERS := $(LIGHTNINGD_OLD_LIB_SRC:.c=.h)

# FIXME: put in a library so we don't link all of them.
LIGHTNINGD_LIB_SRC :=				\
	lightningd/channel.c			\
	lightningd/channel_config.c		\
	lightningd/commit_tx.c			\
	lightningd/cryptomsg.c			\
	lightningd/crypto_sync.c		\
	lightningd/debug.c			\
	lightningd/daemon_conn.c		\
	lightningd/derive_basepoints.c		\
	lightningd/dev_disconnect.c		\
	lightningd/funding_tx.c			\
	lightningd/gossip_msg.c			\
	lightningd/htlc_tx.c			\
	lightningd/htlc_wire.c			\
	lightningd/key_derive.c			\
	lightningd/msg_queue.c			\
	lightningd/peer_failed.c		\
	lightningd/ping.c			\
	lightningd/sphinx.c			\
	lightningd/status.c			\
	lightningd/utxo.c			\
	lightningd/withdraw_tx.c

LIGHTNINGD_LIB_OBJS := $(LIGHTNINGD_LIB_SRC:.c=.o)
LIGHTNINGD_LIB_HEADERS := $(LIGHTNINGD_LIB_SRC:.c=.h)

LIGHTNINGD_SRC :=				\
	lightningd/build_utxos.c		\
	lightningd/dev_ping.c			\
	lightningd/gossip_control.c		\
	lightningd/htlc_end.c			\
	lightningd/hsm_control.c		\
	lightningd/lightningd.c			\
	lightningd/new_connection.c		\
	lightningd/pay.c			\
	lightningd/peer_control.c		\
	lightningd/peer_htlcs.c			\
	lightningd/subd.c

LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o)

LIGHTNINGD_JSMN_OBJS := daemon/jsmn.o
LIGHTNINGD_JSMN_HEADERS := daemon/jsmn/jsmn.h

# We accumulate all lightningd/ headers in these three:
LIGHTNINGD_HEADERS_NOGEN =			\
	lightningd/build_utxos.h		\
	lightningd/gossip_control.h		\
	lightningd/hsm_control.h		\
	lightningd/htlc_end.h			\
	lightningd/lightningd.h			\
	lightningd/new_connection.h		\
	lightningd/pay.h			\
	lightningd/peer_control.h		\
	lightningd/peer_htlcs.h			\
	lightningd/peer_state.h			\
	lightningd/subd.h			\
	$(LIGHTNINGD_OLD_LIB_HEADERS)		\
	$(LIGHTNINGD_LIB_HEADERS)		\
	$(WIRE_HEADERS)				\
	$(BITCOIN_HEADERS)			\
	$(CORE_HEADERS)				\
	$(CORE_TX_HEADERS)			\
	$(DAEMON_HEADERS)			\
	$(WALLET_LIB_HEADERS)

# Generated headers
LIGHTNINGD_HEADERS_GEN =			\
	lightningd/gen_peer_state_names.h	\
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

$(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS): $(LIGHTNINGD_HEADERS) 

lightningd/gen_peer_state_names.h: lightningd/peer_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/peer_state.h > $@

check-source: $(LIGHTNINGD_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_LIB_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_CLI_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_HEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_SRC:%=bolt-check/%) $(LIGHTNINGD_LIB_SRC:%=bolt-check/%) $(LIGHTNINGD_HEADERS_NOGEN:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_SRC:%=check-whitespace/%) $(LIGHTNINGD_HEADERS_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_LIB_SRC:%=check-whitespace/%) $(LIGHTNINGD_LIB_HEADERS:%=check-whitespace/%)

check-makefile: check-lightningd-makefile
check-lightningd-makefile:
	@for f in lightningd/*.h lightningd/*/*.h; do if ! echo $(LIGHTNINGD_HEADERS_NOGEN) $(LIGHTNINGD_HEADERS_GEN) "" | grep -q "$$f "; then echo $$f not mentioned in LIGHTNINGD_HEADERS_NOGEN or LIGHTNINGD_HEADERS_GEN >&2; exit 1; fi; done

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(LIGHTNINGD_OLD_OBJS) $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_JSMN_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_HSM_CONTROL_OBJS) $(LIGHTNINGD_HANDSHAKE_CONTROL_OBJS) $(LIGHTNINGD_GOSSIP_CONTROL_OBJS) $(LIBBASE58_OBJS) $(LIGHTNINGD_OPENING_CONTROL_OBJS) $(LIGHTNINGD_CHANNEL_CONTROL_OBJS) $(WALLET_LIB_OBJS) libsecp256k1.a libsodium.a libwallycore.a

clean: lightningd-clean

lightningd-clean:
	$(RM) $(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_JSMN_OBJS) 

include lightningd/test/Makefile
