#! /usr/bin/make

LANG=C
LC_ALL=C
LC_CTYPE=C

# Designed to be run one level up
daemon-wrongdir:
	$(MAKE) -C .. daemon-all

daemon-all: daemon/lightningd daemon/lightning-cli

DAEMON_LIB_SRC :=				\
	daemon/configdir.c			\
	daemon/json.c				\
	daemon/log.c				\
	daemon/pseudorand.c
DAEMON_LIB_OBJS := $(DAEMON_LIB_SRC:.c=.o)

DAEMON_SRC :=					\
	daemon/bitcoind.c			\
	daemon/broadcast.c			\
	daemon/chaintopology.c			\
	daemon/channel.c			\
	daemon/commit_tx.c			\
	daemon/cryptopkt.c			\
	daemon/db.c				\
	daemon/dns.c				\
	daemon/failure.c			\
	daemon/feechange.c			\
	daemon/htlc.c				\
	daemon/htlc_state.c			\
	daemon/invoice.c			\
	daemon/irc_announce.c			\
	daemon/jsonrpc.c			\
	daemon/lightningd.c			\
	daemon/netaddr.c			\
	daemon/options.c			\
	daemon/opt_time.c			\
	daemon/output_to_htlc.c			\
	daemon/p2p_announce.c			\
	daemon/packets.c			\
	daemon/pay.c				\
	daemon/peer.c				\
	daemon/routing.c			\
	daemon/routingrpc.c			\
	daemon/secrets.c			\
	daemon/sphinx.c				\
	daemon/timeout.c			\
	daemon/wallet.c				\
	daemon/watch.c				\
	daemon/names.c				\
	irc.c

DAEMON_OBJS := $(DAEMON_SRC:.c=.o)

DAEMON_CLI_SRC := daemon/lightning-cli.c
DAEMON_CLI_OBJS := $(DAEMON_CLI_SRC:.c=.o)

DAEMON_JSMN_OBJS := daemon/jsmn.o
DAEMON_JSMN_HEADERS := daemon/jsmn/jsmn.h

DAEMON_GEN_HEADERS :=				\
	daemon/gen_feechange_state_names.h	\
	daemon/gen_htlc_state_names.h		\
	daemon/gen_pkt_names.h			\
	daemon/gen_state_names.h

DAEMON_HEADERS :=				\
	daemon/bitcoind.h			\
	daemon/broadcast.h			\
	daemon/chaintopology.h			\
	daemon/channel.h			\
	daemon/commit_tx.h			\
	daemon/configdir.h			\
	daemon/cryptopkt.h			\
	daemon/db.h				\
	daemon/dns.h				\
	daemon/failure.h			\
	daemon/feechange.h			\
	daemon/feechange_state.h		\
	daemon/htlc.h				\
	daemon/htlc_state.h			\
	daemon/invoice.h			\
	daemon/irc_announce.h			\
	daemon/json.h				\
	daemon/jsonrpc.h			\
	daemon/lightningd.h			\
	daemon/log.h				\
	daemon/names.h				\
	daemon/netaddr.h			\
	daemon/opt_time.h			\
	daemon/options.h			\
	daemon/output_to_htlc.h			\
	daemon/p2p_announce.h			\
	daemon/packets.h			\
	daemon/pay.h				\
	daemon/peer.h				\
	daemon/peer_internal.h			\
	daemon/pseudorand.h			\
	daemon/routing.h			\
	daemon/secrets.h			\
	daemon/sphinx.h				\
	daemon/state.h				\
	daemon/state_types.h			\
	daemon/timeout.h			\
	daemon/wallet.h				\
	daemon/watch.h

daemon/gen_htlc_state_names.h: daemon/htlc_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr daemon/htlc_state.h > $@

daemon/gen_feechange_state_names.h: daemon/feechange_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr daemon/feechange_state.h > $@

daemon/gen_state_names.h: daemon/state_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr daemon/state_types.h > $@

# lightning.pb-c.h doesn't create a named enum, just a typedef.  Hack it.
daemon/gen_pkt_names.h: lightning.pb-c.h ccan/ccan/cdump/tools/cdump-enumstr
	(echo 'enum PktCase {'; grep '^  PKT__' lightning.pb-c.h; echo '};') | 	ccan/ccan/cdump/tools/cdump-enumstr - | sed 's/enum PktCase/Pkt__PktCase/' > $@

$(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_CLI_OBJS): $(DAEMON_HEADERS) $(DAEMON_JSMN_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(CORE_TX_HEADERS) $(GEN_HEADERS) $(DAEMON_GEN_HEADERS) $(CCAN_HEADERS) $(WIRE_HEADERS) $(WIRE_GEN_HEADERS) $(LIBSODIUM_HEADERS) $(LIBBASE58_HEADERS)
$(DAEMON_JSMN_OBJS): $(DAEMON_JSMN_HEADERS)

$(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_CLI_OBJS): CFLAGS += -USHACHAIN_BITS

check-source: $(DAEMON_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_LIB_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_CLI_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_HEADERS:%=check-hdr-include-order/%)
check-daemon-makefile:
	@echo $(DAEMON_HEADERS) | tr ' ' '\012' > /tmp/daemon-headers-makefile
	@ls daemon/*.h | grep -v daemon/gen > /tmp/daemon-headers-file
	@if [ "`diff -w /tmp/daemon-headers-makefile /tmp/daemon-headers-file`" != "" ]; then echo DAEMON_HEADERS incorrect; diff -w --context=2 /tmp/daemon-headers-makefile /tmp/daemon-headers-file; exit 1; fi
	@rm /tmp/daemon-headers-makefile /tmp/daemon-headers-file

check-source-bolt: $(DAEMON_SRC:%=bolt-check/%) $(DAEMON_HEADERS:%=bolt-check/%)

check-whitespace: $(DAEMON_SRC:%=check-whitespace/%) $(DAEMON_HEADERS:%=check-whitespace/%) check-whitespace/daemon/Makefile

# Git submodules are seriously broken.
daemon/jsmn/jsmn.h:
	git submodule update daemon/jsmn/
	[ -f $@ ] || git submodule update --init daemon/jsmn/

# If we tell Make that the above builds both, it runs it twice in
# parallel.  So we lie :(
daemon/jsmn/jsmn.c: daemon/jsmn/jsmn.h
	[ -f $@ ]

daemon/jsmn.o: daemon/jsmn/jsmn.c
	$(COMPILE.c) -DJSMN_STRICT=1 $(OUTPUT_OPTION) $<

# We need a 64-bit shachain (default)
daemon/shachain-64.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c $(CCAN_HEADERS)
	$(CC) $(CFLAGS) -USHACHAIN_BITS -c -o $@ $<

daemon/lightningd: $(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_JSMN_OBJS) $(CORE_OBJS)  $(CORE_TX_OBJS) $(CORE_PROTOBUF_OBJS) $(BITCOIN_OBJS) $(LIBBASE58_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) daemon/shachain-64.o libsecp256k1.a libsodium.a

daemon/lightning-cli: $(DAEMON_CLI_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_JSMN_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(LIBBASE58_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) libsecp256k1.a libsodium.a

daemon-clean:
	$(RM) $(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_CLI_OBJS) $(DAEMON_JSMN_OBJS) $(DAEMON_GEN_HEADERS)

daemon-maintainer-clean:

include daemon/test/Makefile
