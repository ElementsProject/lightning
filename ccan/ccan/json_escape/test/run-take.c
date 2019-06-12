#include <ccan/json_escape/json_escape.h>
/* Include the C files directly. */
#include <ccan/json_escape/json_escape.c>
#include <ccan/tap/tap.h>

int main(void)
{
	const tal_t *ctx = tal(NULL, char);
	struct json_escape *e;
	char *p;

	/* This is how many tests you plan to run */
	plan_tests(5);

	/* This should simply be tal_steal */
	p = tal_dup_arr(NULL, char, "Hello", 6, 0);
	e = json_escape(ctx, take(p));
	ok1(!strcmp(e->s, "Hello"));
	ok1((void *)e == (void *)p);
	ok1(tal_parent(e) == ctx);

	/* This can't be tal_steal, but still should be freed. */
	p = tal_dup_arr(NULL, char,
			"\\\b\f\n\r\t\""
			"\\\\\\b\\f\\n\\r\\t\\\"", 22, 0);
	e = json_escape(ctx, take(p));
	ok1(tal_parent(e) == ctx);
	ok1(!strcmp(e->s,
		    "\\\\\\b\\f\\n\\r\\t\\\""
		    "\\\\\\\\\\\\b\\\\f\\\\n\\\\r\\\\t\\\\\\\""));
	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
