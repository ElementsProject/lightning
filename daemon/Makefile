#! /usr/bin/make

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
	daemon/chaintopology.c			\
	daemon/channel.c			\
	daemon/commit_tx.c			\
	daemon/controlled_time.c		\
	daemon/cryptopkt.c			\
	daemon/db.c				\
	daemon/dns.c				\
	daemon/failure.c			\
	daemon/feechange.c			\
	daemon/htlc.c				\
	daemon/invoice.c			\
	daemon/irc_announce.c			\
	daemon/jsonrpc.c			\
	daemon/lightningd.c			\
	daemon/netaddr.c			\
	daemon/opt_time.c			\
	daemon/output_to_htlc.c			\
	daemon/packets.c			\
	daemon/pay.c				\
	daemon/peer.c				\
	daemon/routing.c			\
	daemon/secrets.c			\
	daemon/sphinx.c				\
	daemon/timeout.c			\
	daemon/wallet.c				\
	daemon/watch.c				\
	names.c					\
	irc.c

DAEMON_OBJS := $(DAEMON_SRC:.c=.o)

DAEMON_CLI_SRC := daemon/lightning-cli.c
DAEMON_CLI_OBJS := $(DAEMON_CLI_SRC:.c=.o)

DAEMON_JSMN_OBJS := daemon/jsmn.o
DAEMON_JSMN_HEADERS := daemon/jsmn/jsmn.h

DAEMON_GEN_HEADERS :=				\
	daemon/gen_feechange_state_names.h	\
	daemon/gen_htlc_state_names.h 

DAEMON_HEADERS :=				\
	daemon/bitcoind.h			\
	daemon/chaintopology.h			\
	daemon/channel.h			\
	daemon/commit_tx.h			\
	daemon/configdir.h			\
	daemon/controlled_time.h		\
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
	daemon/netaddr.h			\
	daemon/opt_time.h			\
	daemon/output_to_htlc.h			\
	daemon/packets.h			\
	daemon/pay.h				\
	daemon/peer.h				\
	daemon/pseudorand.h			\
	daemon/routing.h			\
	daemon/secrets.h			\
	daemon/sphinx.h				\
	daemon/timeout.h			\
	daemon/wallet.h				\
	daemon/watch.h

daemon/gen_htlc_state_names.h: daemon/htlc_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr daemon/htlc_state.h > $@

daemon/gen_feechange_state_names.h: daemon/feechange_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr daemon/feechange_state.h > $@

$(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_CLI_OBJS): $(DAEMON_HEADERS) $(DAEMON_JSMN_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(DAEMON_GEN_HEADERS) $(CCAN_HEADERS)
$(DAEMON_JSMN_OBJS): $(DAEMON_JSMN_HEADERS)

check-source: $(DAEMON_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_LIB_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_CLI_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_HEADERS:%=check-hdr-include-order/%)
check-daemon-makefile:
	@if [ "`ls daemon/*.h | grep -v daemon/gen | tr '\012' ' '`" != "`echo $(DAEMON_HEADERS) ''`" ]; then echo DAEMON_HEADERS incorrect; exit 1; fi

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

daemon/lightningd: $(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_JSMN_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) libsecp256k1.a

daemon/lightning-cli: $(DAEMON_CLI_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_JSMN_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) libsecp256k1.a

daemon-clean:
	$(RM) $(DAEMON_OBJS) $(DAEMON_LIB_OBJS) $(DAEMON_CLI_OBJS) $(DAEMON_JSMN_OBJS)

daemon-maintainer-clean:
	$(RM) $(DAEMON_GEN_HEADERS)

include daemon/test/Makefile
