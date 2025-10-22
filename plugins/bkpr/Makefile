#! /usr/bin/make

BOOKKEEPER_PLUGIN_SRC := 			\
	plugins/bkpr/account.c			\
	plugins/bkpr/account_entry.c		\
	plugins/bkpr/blockheights.c		\
	plugins/bkpr/bookkeeper.c		\
	plugins/bkpr/chain_event.c		\
	plugins/bkpr/channel_event.c		\
	plugins/bkpr/channelsapy.c		\
	plugins/bkpr/descriptions.c		\
	plugins/bkpr/incomestmt.c		\
	plugins/bkpr/onchain_fee.c		\
	plugins/bkpr/rebalances.c		\
	plugins/bkpr/recorder.c			\
	plugins/bkpr/sql.c

BOOKKEEPER_SRC := $(BOOKKEEPER_PLUGIN_SRC) $(BOOKKEEPER_DB_QUERIES)
BOOKKEEPER_HEADER := 				\
	plugins/bkpr/account.h			\
	plugins/bkpr/account_entry.h		\
	plugins/bkpr/blockheights.h		\
	plugins/bkpr/bookkeeper.h		\
	plugins/bkpr/chain_event.h		\
	plugins/bkpr/channel_event.h		\
	plugins/bkpr/channelsapy.h		\
	plugins/bkpr/descriptions.h		\
	plugins/bkpr/incomestmt.h		\
	plugins/bkpr/onchain_fee.h		\
	plugins/bkpr/rebalances.h		\
	plugins/bkpr/recorder.h			\
	plugins/bkpr/sql.h

BOOKKEEPER_OBJS := $(BOOKKEEPER_SRC:.c=.o)

$(BOOKKEEPER_OBJS): $(PLUGIN_LIB_HEADER) $(BOOKKEEPER_HEADER)

PLUGIN_ALL_SRC += $(BOOKKEEPER_SRC)
PLUGIN_ALL_HEADER += $(BOOKKEEPER_HEADER)
C_PLUGINS += plugins/bookkeeper
PLUGINS += plugins/bookkeeper

plugins/bookkeeper: $(BOOKKEEPER_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

maintainer-clean: clean
clean: bkpr-maintainer-clean
bkpr-maintainer-clean:
	$(RM) plugins/bkpr/statements.po
	$(RM) plugins/bkpr/statements_gettextgen.po
	$(RM) $(BOOKKEEPER_DB_QUERIES)

include plugins/bkpr/test/Makefile
