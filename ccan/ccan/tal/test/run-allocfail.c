#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static int alloc_count, when_to_fail, err_count;
static bool stealing;

static void *failing_alloc(size_t len)
{
	if (alloc_count++ == when_to_fail)
		return NULL;
	/* once we've failed once, it shouldn't ask again (steal can though). */
	assert(stealing || alloc_count <= when_to_fail);

	return malloc(len);
}

static void *failing_realloc(void *p, size_t len)
{
	if (alloc_count++ == when_to_fail)
		return NULL;

	return realloc(p, len);
}


static void nofail_on_error(const char *msg)
{
	diag("ERROR: %s", msg);
	err_count++;
}

static void destroy_p(void *p UNNEEDED)
{
}

int main(void)
{
	char *p, *c1, *c2;
	bool success;

	plan_tests(25);

	tal_set_backend(failing_alloc, failing_realloc, NULL, nofail_on_error);

	/* Fail at each possible point in an allocation. */
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		p = tal(NULL, char);
		when_to_fail++;
	} while (!p);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	/* Do it again. */
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		c1 = tal(p, char);
		when_to_fail++;
	} while (!c1);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	/* Now during resize. */
	c2 = c1;
	when_to_fail = err_count = 0;
	for (;;) {
		alloc_count = 0;
		if (tal_resize(&c1, 100))
			break;
		/* Failing alloc will not change pointer. */
		ok1(c1 == c2);
		when_to_fail++;
	};
	ok1(alloc_count == 1);
	ok1(when_to_fail == 1);
	ok1(err_count == 1);
	/* Make sure it's really resized. */
	memset(c1, 1, 100);

	/* Now for second child. */
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		c2 = tal(p, char);
		when_to_fail++;
	} while (!c2);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	/* Note: adding a child will fall through if group alloc fails. */
	ok1 (err_count == when_to_fail - 1 || err_count == when_to_fail);

	/* Now while adding a destructor. */
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		success = tal_add_destructor(p, destroy_p);
		when_to_fail++;
	} while (!success);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	/* Now while adding a name. */
	when_to_fail = err_count = 0;
	do {
		const char name[] = "some name";
		alloc_count = 0;
		success = tal_set_name(p, name);
		when_to_fail++;
	} while (!success);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	/* Now while stealing. */
	stealing = true;
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		success = tal_steal(c2, c1) != NULL;
		when_to_fail++;
	} while (!success);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	/* Now stealing with more children (more coverage). */
	when_to_fail = 1000;
	(void)tal(p, char);
	c1 = tal(p, char);
	c2 = tal(p, char);
	(void)tal(p, char);

	/* Now steal again. */
	when_to_fail = err_count = 0;
	do {
		alloc_count = 0;
		success = tal_steal(c2, c1) != NULL;
		when_to_fail++;
	} while (!success);
	ok1(alloc_count >= 1);
	ok1(when_to_fail > 1);
	ok1(err_count == when_to_fail - 1);

	tal_free(p);
	tal_cleanup();
	return exit_status();
}
