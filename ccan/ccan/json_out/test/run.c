#include <ccan/json_out/json_out.h>
/* Include the C files directly. */
#include <ccan/json_out/json_out.c>
#include <ccan/tap/tap.h>

static void test_json_out_add(const tal_t *ctx,
			      char c, bool quote, const char *escaped)
{
	/* 64 is the size of the initial buf, so we test that. */
	for (size_t i = 1; i < 64; i++) {
		struct json_out *jout;
		char str[64 + 1];
		const char *r;
		size_t len;
		char fieldname[64 + 1];

		jout = json_out_new(ctx);
		json_out_start(jout, NULL, '{');
		memset(str, c, i);
		str[i] = '\0';
		memset(fieldname, 'f', i);
		fieldname[i] = '\0';
		json_out_add(jout, fieldname, quote, "%s", str);
		json_out_end(jout, '}');
		json_out_finished(jout);

		r = json_out_contents(jout, &len);
		ok1(len == strlen("{\"") + i + strlen("\":")
		    + quote * 2 + strlen(escaped) * i + strlen("}"));

		ok1(len > strlen("{\""));
		ok1(memcmp(r, "{\"", strlen("{\"")) == 0);
		json_out_consume(jout, strlen("{\""));

		r = json_out_contents(jout, &len);
		ok1(len > strlen(fieldname));
		ok1(memcmp(r, fieldname, strlen(fieldname)) == 0);
		json_out_consume(jout, strlen(fieldname));

		r = json_out_contents(jout, &len);
		ok1(len > strlen("\":"));
		ok1(memcmp(r, "\":", strlen("\":")) == 0);
		json_out_consume(jout, strlen("\":"));

		r = json_out_contents(jout, &len);
		if (quote) {
			ok1(len > 0);
			ok1(r[0] == '"');
			json_out_consume(jout, 1);
		}
		for (size_t n = 0; n < i; n++) {
			r = json_out_contents(jout, &len);
			ok1(len > strlen(escaped));
			ok1(memcmp(r, escaped, strlen(escaped)) == 0);
			json_out_consume(jout, strlen(escaped));
		}
		r = json_out_contents(jout, &len);
		if (quote) {
			ok1(len > 0);
			ok1(r[0] == '"');
			json_out_consume(jout, 1);
		}
		r = json_out_contents(jout, &len);
		ok1(len == 1);
		ok1(memcmp(r, "}", 1) == 0);
		json_out_consume(jout, 1);
		ok1(!json_out_contents(jout, &len));
		ok1(len == 0);
	}
}

static void json_eq(const struct json_out *jout, const char *expect)
{
	size_t len;
	const char *p;

	json_out_finished(jout);
	p = json_out_contents(jout, &len);
	ok1(len == strlen(expect));
	ok1(memcmp(expect, p, len) == 0);
}
	
int main(void)
{
	const tal_t *ctx = tal(NULL, char);
	struct json_out *jout;
	char *p;

	/* This is how many tests you plan to run */
	plan_tests(14689);

	/* Simple tests */
	test_json_out_add(ctx, '1', false, "1");
	test_json_out_add(ctx, 'x', true, "x");
	test_json_out_add(ctx, '\n', true, "\\n");

	/* Test nested arrays. */
	jout = json_out_new(ctx);
	for (size_t i = 0; i < 64; i++)
		json_out_start(jout, NULL, '[');
	for (size_t i = 0; i < 64; i++)
		json_out_end(jout, ']');
	json_eq(jout, "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]");

	/* Test nested objects. */
	jout = json_out_new(ctx);
	json_out_start(jout, NULL, '{');
	for (size_t i = 0; i < 63; i++)
		json_out_start(jout, "x", '{');
	for (size_t i = 0; i < 64; i++)
		json_out_end(jout, '}');
	json_eq(jout, "{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{\"x\":{}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}");

	jout = json_out_new(ctx);
	json_out_start(jout, NULL, '{');
	p = json_out_member_direct(jout, "x", 7);
	memcpy(p, "\"hello\"", 7);
	json_out_end(jout, '}');
	json_eq(jout, "{\"x\":\"hello\"}");

	jout = json_out_new(ctx);
	p = json_out_direct(jout, strlen("{\"x\":\"hello\"}\n"));
	memcpy(p, "{\"x\":\"hello\"}\n", strlen("{\"x\":\"hello\"}\n"));
	json_eq(jout, "{\"x\":\"hello\"}\n");

	jout = json_out_new(ctx);
	json_out_start(jout, NULL, '{');
	struct json_out *jout2 = json_out_new(ctx);
	json_out_start(jout2, NULL, '{');
	json_out_addstr(jout2, "x", "hello");
	json_out_end(jout2, '}');
	json_out_finished(jout2);
	json_out_add_splice(jout, "inner", jout2);
	json_out_end(jout, '}');
	json_eq(jout, "{\"inner\":{\"x\":\"hello\"}}");

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
