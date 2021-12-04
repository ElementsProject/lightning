#include <ccan/json_out/json_out.h>
/* Include the C files directly. */
#include <ccan/json_out/json_out.c>
#include <ccan/tap/tap.h>

static const char *ptr;
static bool called = false;

static void move_cb(struct json_out *jout, ptrdiff_t delta,
		    struct json_out *arg)
{
	ptr += delta;
	called = true;
	ok1(arg == jout);
}

int main(void)
{
	const tal_t *ctx = tal(NULL, char);
	struct json_out *jout;
	char *p;
	size_t len;

	/* This is how many tests you plan to run */
	plan_tests(3);

	/* Test nested arrays. */
	jout = json_out_new(ctx);
	json_out_call_on_move(jout, move_cb, jout);

	json_out_start(jout, NULL, '{');
	ptr = json_out_contents(jout, &len);

	p = json_out_member_direct(jout, "fieldname", 102);
	p[0] = '"';
	p[101] = '"';
	memset(p+1, 'p', 100);

	json_out_finished(jout);
	ok1(called);
	/* Contents should have moved correctly. */
	ok1(json_out_contents(jout, &len) == ptr);

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
