#ifndef LIGHTNING_PLUGINS_BKPR_DB_H
#define LIGHTNING_PLUGINS_BKPR_DB_H
#include "config.h"
#include <ccan/tal/tal.h>

struct plugin;
struct db;

struct db *db_setup(const tal_t *ctx, struct plugin *p, const char *db_dsn);

#endif /* LIGHTNING_PLUGINS_BKPR_DB_H */
