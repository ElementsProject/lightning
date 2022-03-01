#! /usr/bin/make

WALLET_LIB_SRC :=		\
	wallet/db.c		\
	wallet/invoices.c	\
	wallet/txfilter.c	\
	wallet/wallet.c		\
	wallet/walletrpc.c

WALLET_LIB_SRC_NOHDR :=			\
	wallet/reservation.c

WALLET_DB_QUERIES  := 			\
	wallet/db_sqlite3_sqlgen.c 	\
	wallet/db_postgres_sqlgen.c

WALLET_SRC := $(WALLET_LIB_SRC) $(WALLET_LIB_SRC_NOHDR) $(WALLET_DB_QUERIES)
WALLET_HDRS := $(WALLET_LIB_SRC:.c=.h)

WALLET_OBJS := $(WALLET_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(WALLET_SRC) $(WALLET_DB_QUERIES)
ALL_C_HEADERS += $(WALLET_HDRS)

# The following files contain SQL-annotated statements that we need to extact
WALLET_SQL_FILES := 			\
	$(DB_SQL_FILES)			\
	wallet/db.c 			\
	wallet/invoices.c		\
	wallet/wallet.c 		\
	wallet/test/run-db.c		\
	wallet/test/run-wallet.c	\

wallet/statements_gettextgen.po: $(WALLET_SQL_FILES) $(FORCE)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"xgettext $@",xgettext -kNAMED_SQL -kSQL --add-location --no-wrap --omit-header -o $@ $(WALLET_SQL_FILES) && $(call SHA256STAMP,# ,)); \
	fi

wallet/db_%_sqlgen.c: wallet/statements_gettextgen.po devtools/sql-rewrite.py $(FORCE)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"sql-rewrite $@",devtools/sql-rewrite.py wallet/statements_gettextgen.po $* > $@ && $(call SHA256STAMP,//,)); \
	fi

maintainer-clean: clean
clean: wallet-maintainer-clean
wallet-maintainer-clean:
	$(RM) wallet/statements.po
	$(RM) wallet/statements_gettextgen.po
	$(RM) $(WALLET_DB_QUERIES)

include wallet/test/Makefile
