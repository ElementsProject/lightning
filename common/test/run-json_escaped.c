#include "../json_escaped.c"
#include <assert.h>
#include <common/utils.h>
#include <stdio.h>

static void test_json_partial(void)
{
	const tal_t *ctx = tal(NULL, char);

	assert(streq(json_partial_escape(ctx, "\\")->s, "\\\\"));
	assert(streq(json_partial_escape(ctx, "\\\\")->s, "\\\\"));
	assert(streq(json_partial_escape(ctx, "\\\\\\")->s, "\\\\\\\\"));
	assert(streq(json_partial_escape(ctx, "\\\\\\\\")->s, "\\\\\\\\"));
	assert(streq(json_partial_escape(ctx, "\\n")->s, "\\n"));
	assert(streq(json_partial_escape(ctx, "\n")->s, "\\n"));
	assert(streq(json_partial_escape(ctx, "\\\"")->s, "\\\""));
	assert(streq(json_partial_escape(ctx, "\"")->s, "\\\""));
	assert(streq(json_partial_escape(ctx, "\\t")->s, "\\t"));
	assert(streq(json_partial_escape(ctx, "\t")->s, "\\t"));
	assert(streq(json_partial_escape(ctx, "\\b")->s, "\\b"));
	assert(streq(json_partial_escape(ctx, "\b")->s, "\\b"));
	assert(streq(json_partial_escape(ctx, "\\r")->s, "\\r"));
	assert(streq(json_partial_escape(ctx, "\r")->s, "\\r"));
	assert(streq(json_partial_escape(ctx, "\\f")->s, "\\f"));
	assert(streq(json_partial_escape(ctx, "\f")->s, "\\f"));
	/* You're allowed to escape / according to json.org. */
	assert(streq(json_partial_escape(ctx, "\\/")->s, "\\/"));
	assert(streq(json_partial_escape(ctx, "/")->s, "/"));

	assert(streq(json_partial_escape(ctx, "\\u0FFF")->s, "\\u0FFF"));
	assert(streq(json_partial_escape(ctx, "\\u0FFFx")->s, "\\u0FFFx"));

	/* Unknown escapes should be escaped. */
	assert(streq(json_partial_escape(ctx, "\\x")->s, "\\\\x"));
	tal_free(ctx);
}


int main(void)
{
	setup_locale();

	test_json_partial();
	assert(!taken_any());
	take_cleanup();
}
