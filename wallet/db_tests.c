#include "db.c"

#include <stdio.h>
#include <unistd.h>

static struct db *create_test_db(const char *testname)
{
	struct db *db;
	char filename[] = "/tmp/ldb-XXXXXX";

	int fd = mkstemp(filename);
	if (fd == -1)
		return NULL;
	close(fd);

	db = db_open(NULL, filename);
	return db;
}

static bool test_empty_db_migrate(void)
{
	struct db *db = create_test_db(__func__);
	if (!db)
		goto fail;

	if (db_get_version(db) != -1)
		goto fail;

	if (!db_migrate(db))
		goto fail;

	if (db_get_version(db) != db_migration_count())
		goto fail;

	tal_free(db);
	return true;
fail:
	printf("Migration failed with error: %s\n", db->err);
	tal_free(db);
	return false;
}

int main(void)
{
	bool ok = true;

	ok &= test_empty_db_migrate();

	return !ok;
}
