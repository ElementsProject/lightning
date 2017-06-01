#include "db.c"

#include "wallet/test_utils.h"

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
	CHECK(db);
	CHECK(db_get_version(db) == -1);
	CHECK(db_migrate(db));
	CHECK(db_get_version(db) == db_migration_count());

	tal_free(db);
	return true;
}

static bool test_vars(void)
{
	struct db *db = create_test_db(__func__);
	char *varname = "testvar";
	CHECK(db);
	CHECK(db_migrate(db));

	/* Check default behavior */
	CHECK(db_get_intvar(db, varname, 42) == 42);

	/* Check setting and getting */
	CHECK(db_set_intvar(db, varname, 1));
	CHECK(db_get_intvar(db, varname, 42) == 1);

	/* Check updating */
	CHECK(db_set_intvar(db, varname, 2));
	CHECK(db_get_intvar(db, varname, 42) == 2);

	tal_free(db);
	return true;
}

int main(void)
{
	bool ok = true;

	ok &= test_empty_db_migrate();
	ok &= test_vars();

	return !ok;
}
