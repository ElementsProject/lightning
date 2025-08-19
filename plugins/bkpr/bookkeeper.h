#ifndef LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H
#define LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H

#include "config.h"

struct bkpr {
	/* The database that we store all the accounting data in */
	struct db *db;

	char *db_dsn;
	char *datadir;
};

#endif /* LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H */
