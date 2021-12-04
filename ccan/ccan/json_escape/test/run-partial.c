#include <ccan/json_escape/json_escape.h>
/* Include the C files directly. */
#include <ccan/json_escape/json_escape.c>
#include <ccan/tap/tap.h>

int main(void)
{
	const tal_t *ctx = tal(NULL, char);

	/* This is how many tests you plan to run */
	plan_tests(21);

	ok1(!strcmp(json_partial_escape(ctx, "\\")->s, "\\\\"));
	ok1(!strcmp(json_partial_escape(ctx, "\\\\")->s, "\\\\"));
	ok1(!strcmp(json_partial_escape(ctx, "\\\\\\")->s, "\\\\\\\\"));
	ok1(!strcmp(json_partial_escape(ctx, "\\\\\\\\")->s, "\\\\\\\\"));
	ok1(!strcmp(json_partial_escape(ctx, "\\n")->s, "\\n"));
	ok1(!strcmp(json_partial_escape(ctx, "\n")->s, "\\n"));
	ok1(!strcmp(json_partial_escape(ctx, "\\\"")->s, "\\\""));
	ok1(!strcmp(json_partial_escape(ctx, "\"")->s, "\\\""));
	ok1(!strcmp(json_partial_escape(ctx, "\\t")->s, "\\t"));
	ok1(!strcmp(json_partial_escape(ctx, "\t")->s, "\\t"));
	ok1(!strcmp(json_partial_escape(ctx, "\\b")->s, "\\b"));
	ok1(!strcmp(json_partial_escape(ctx, "\b")->s, "\\b"));
	ok1(!strcmp(json_partial_escape(ctx, "\\r")->s, "\\r"));
	ok1(!strcmp(json_partial_escape(ctx, "\r")->s, "\\r"));
	ok1(!strcmp(json_partial_escape(ctx, "\\f")->s, "\\f"));
	ok1(!strcmp(json_partial_escape(ctx, "\f")->s, "\\f"));
	/* You're allowed to escape / according to json.org. */
	ok1(!strcmp(json_partial_escape(ctx, "\\/")->s, "\\/"));
	ok1(!strcmp(json_partial_escape(ctx, "/")->s, "/"));

	ok1(!strcmp(json_partial_escape(ctx, "\\u0FFF")->s, "\\u0FFF"));
	ok1(!strcmp(json_partial_escape(ctx, "\\u0FFFx")->s, "\\u0FFFx"));

	/* Unknown escapes should be escaped. */
	ok1(!strcmp(json_partial_escape(ctx, "\\x")->s, "\\\\x"));
	tal_free(ctx);

	return 0;
}
