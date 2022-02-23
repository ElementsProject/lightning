#! /usr/bin/make

BOOKKEEPER_PLUGIN_SRC := 			\
	plugins/bkpr/account.c			\
	plugins/bkpr/bookkeeper.c		\
	plugins/bkpr/db.c			\
	plugins/bkpr/recorder.c

BOOKKEEPER_DB_QUERIES := 			\
	plugins/bkpr/db_sqlite3_sqlgen.c 	\
	plugins/bkpr/db_postgres_sqlgen.c

BOOKKEEPER_SRC := $(BOOKKEEPER_PLUGIN_SRC) $(BOOKKEEPER_DB_QUERIES)
BOOKKEEPER_HEADER := 				\
	plugins/bkpr/account.h			\
	plugins/bkpr/chain_event.h		\
	plugins/bkpr/channel_event.h		\
	plugins/bkpr/db.h			\
	plugins/bkpr/onchain_fee.h		\
	plugins/bkpr/recorder.h

BOOKKEEPER_OBJS := $(BOOKKEEPER_SRC:.c=.o)

$(BOOKKEEPER_OBJS): $(PLUGIN_LIB_HEADER) $(BOOKKEEPER_HEADER)

ALL_C_SOURCES += $(BOOKKEEPER_SRC)
ALL_C_HEADERS += $(BOOKKEEPER_HEADER)
ALL_PROGRAMS += plugins/bookkeeper

plugins/bookkeeper: common/coin_mvt.o $(BOOKKEEPER_OBJS) $(PLUGIN_LIB_OBJS) $(JSMN_OBJTS) $(CCAN_OBJS) $(PLUGIN_COMMON_OBJS) $(WIRE_OBJS) $(DB_OBJS)

# The following files contain SQL-annotated statements that we need to extact
BOOKKEEPER_SQL_FILES := 			\
	$(DB_SQL_FILES)				\
	plugins/bkpr/db.c			\
	plugins/bkpr/recorder.c

plugins/bkpr/statements_gettextgen.po: $(BOOKKEEPER_SQL_FILES) $(FORCE)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"xgettext $@",xgettext -kNAMED_SQL -kSQL --add-location --no-wrap --omit-header -o $@ $(BOOKKEEPER_SQL_FILES) && $(call SHA256STAMP,# ,)); \
	fi

plugins/bkpr/db_%_sqlgen.c: plugins/bkpr/statements_gettextgen.po devtools/sql-rewrite.py $(BOOKKEEPER_SQL_FILES) $(FORCE)
	@if $(call SHA256STAMP_CHANGED); then \
		$(call VERBOSE,"sql-rewrite $@",devtools/sql-rewrite.py plugins/bkpr/statements_gettextgen.po $* > $@ && $(call SHA256STAMP,//,)); \
	fi

maintainer-clean: clean
clean: bkpr-maintainer-clean
bkpr-maintainer-clean:
	$(RM) plugins/bkpr/statements.po
	$(RM) plugins/bkpr/statements_gettextgen.po
	$(RM) $(BOOKKEEPER_DB_QUERIES)

include plugins/bkpr/test/Makefile
