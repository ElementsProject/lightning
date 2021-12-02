#! /usr/bin/make

WALLET_LIB_SRC :=		\
	wallet/db.c		\
	wallet/invoices.c	\
	wallet/txfilter.c	\
	wallet/wallet.c		\
	wallet/walletrpc.c

WALLET_LIB_SRC_NOHDR :=		\
	wallet/reservation.c

WALLET_DB_DRIVERS :=		\
	wallet/db_postgres.c	\
	wallet/db_sqlite3.c

WALLET_SRC := $(WALLET_LIB_SRC) $(WALLET_LIB_SRC_NOHDR) $(WALLET_DB_DRIVERS)
WALLET_HDRS := $(WALLET_LIB_SRC:.c=.h)

WALLET_OBJS := $(WALLET_SRC:.c=.o)
$(WALLET_OBJS): $(WALLET_HDRS) $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(WALLET_SRC) wallet/db_sqlite3_sqlgen.c wallet/db_postgres_sqlgen.c
ALL_C_HEADERS += $(WALLET_HDRS)

# Each database driver depends on its rewritten statements.
wallet/db_sqlite3.o: wallet/db_sqlite3_sqlgen.c
wallet/db_postgres.o: wallet/db_postgres_sqlgen.c

# The following files contain SQL-annotated statements that we need to extact
SQL_FILES := 				\
	wallet/db.c 			\
	wallet/invoices.c		\
	wallet/wallet.c 		\
	wallet/test/run-db.c		\
	wallet/test/run-wallet.c	\

wallet/statements_gettextgen.po: $(SQL_FILES) $(FORCE)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"xgettext $@",xgettext -kNAMED_SQL -kSQL --add-location --no-wrap --omit-header -o $@ $(SQL_FILES) && $(call SHA256STAMP,# ,)); \
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
	$(RM) wallet/db_sqlite3_sqlgen.c
	$(RM) wallet/db_postgres_sqlgen.c

include wallet/test/Makefile
