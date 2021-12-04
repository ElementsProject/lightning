#include <ccan/json_escape/json_escape.h>
/* Include the C files directly. */
#include <ccan/json_escape/json_escape.c>
#include <ccan/tap/tap.h>

int main(void)
{
	const tal_t *ctx = tal(NULL, char);
	struct json_escape *e;

	/* This is how many tests you plan to run */
	plan_tests(6);

	e = json_escape(ctx, "Hello");
	ok1(!strcmp(e->s, "Hello"));
	ok1(!strcmp(json_escape_unescape(ctx, e),
		    "Hello"));

	e = json_escape(ctx,
			"\\\b\f\n\r\t\""
			"\\\\\\b\\f\\n\\r\\t\\\"");
	ok1(!strcmp(e->s,
		    "\\\\\\b\\f\\n\\r\\t\\\""
		    "\\\\\\\\\\\\b\\\\f\\\\n\\\\r\\\\t\\\\\\\""));
	ok1(!strcmp(json_escape_unescape(ctx, e),
		    "\\\b\f\n\r\t\""
		    "\\\\\\b\\f\\n\\r\\t\\\""));

	/* This one doesn't escape the already-escaped chars */
	e = json_partial_escape(ctx,
				"\\\b\f\n\r\t\""
				"\\\\\\b\\f\\n\\r\\t\\\"");
	ok1(!strcmp(e->s,
		    "\\\\\\b\\f\\n\\r\\t\\\""
		    "\\\\\\b\\f\\n\\r\\t\\\""));
	ok1(!strcmp(json_escape_unescape(ctx, e),
		    "\\\b\f\n\r\t\""
		    "\\\b\f\n\r\t\""));

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
