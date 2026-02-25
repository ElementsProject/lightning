#! /usr/bin/make

LIGHTNINGD_SRC :=				\
	lightningd/anchorspend.c		\
	lightningd/bitcoind.c			\
	lightningd/chaintopology.c		\
	lightningd/channel.c			\
	lightningd/channel_control.c		\
	lightningd/channel_gossip.c		\
	lightningd/closing_control.c		\
	lightningd/coin_mvts.c			\
	lightningd/dual_open_control.c		\
	lightningd/closed_channel.c		\
	lightningd/connect_control.c		\
	lightningd/onion_message.c		\
	lightningd/feerate.c			\
	lightningd/forwards.c			\
	lightningd/gossip_control.c		\
	lightningd/gossip_generation.c		\
	lightningd/hsm_control.c		\
	lightningd/htlc_end.c			\
	lightningd/htlc_set.c			\
	lightningd/invoice.c			\
	lightningd/io_loop_with_timers.c	\
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
	lightningd/ping.c			\
	lightningd/plugin.c			\
	lightningd/plugin_control.c		\
	lightningd/plugin_hook.c		\
	lightningd/routehint.c			\
	lightningd/runes.c			\
	lightningd/subd.c			\
	lightningd/wait.c			\
	lightningd/watchman.c

LIGHTNINGD_SRC_NOHDR :=				\
	lightningd/configs.c			\
	lightningd/datastore.c			\
	lightningd/offer.c			\
	lightningd/signmessage.c

include wallet/Makefile

LIGHTNINGD_HDRS :=				\
	$(LIGHTNINGD_SRC:.c=.h)			\
	lightningd/channel_state.h		\
	lightningd/channel_state_names_gen.h	\
	$(WALLET_HDRS)


LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o) $(LIGHTNINGD_SRC_NOHDR:.c=.o)
$(LIGHTNINGD_OBJS): $(LIGHTNINGD_HDRS) $(LIGHTNINGD_CONTROL_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(LIGHTNINGD_SRC) $(LIGHTNINGD_SRC_NOHDR)
ALL_C_HEADERS += $(LIGHTNINGD_HDRS)
ALL_PROGRAMS += lightningd/lightningd

# We explicitly check header versions in lightningd.c
lightningd/lightningd.o: header_versions_gen.h

$(LIGHTNINGD_OBJS): $(LIGHTNINGD_HDRS)
$(WALLET_OBJS): $(LIGHTNINGD_HDRS) $(DB_HEADERS) plugins/bwatch/bwatch_wiregen.h

# Only the plugin component needs to depend on this header.
lightningd/plugin.o: plugins/list_of_builtin_plugins_gen.h

lightningd/channel_state_names_gen.h: lightningd/channel_state.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/channel_state.h > $@

# bwatch wire format for reading utxoset from datastore (shared with bwatch plugin)
BWATCH_WIRE_OBJ := plugins/bwatch/bwatch_wiregen.o

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(WALLET_OBJS) $(BWATCH_WIRE_OBJ) $(LIGHTNINGD_CONTROL_OBJS) $(HSMD_CLIENT_OBJS) $(DB_OBJS) libcommon.a

include lightningd/test/Makefile
