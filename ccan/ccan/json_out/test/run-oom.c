/* Regression test (auditor-added, temporary): json_out's documented OOM
 * contract is graceful failure:
 *   json_out_add:           "Returns true unless tal_resize() fails."
 *   json_out_member_direct: "Returns ... or NULL if tal_resize() fails."
 *   json_out_direct:        "Returns ... or NULL if tal_resize() fails."
 *   json_out_add_splice:    "Returns false if tal_resize() fails."
 *
 * But mkroom() (ccan/json_out/json_out.c:119-127) never checks whether
 * membuf_prepare_space() actually made room (membuf.h documents the
 * failure check: membuf_num_space() < num_extra), so on tal_resize
 * failure it returns a pointer into the too-small old buffer and
 * callers write past the end (heap buffer overflow) or hit the
 * membuf_added() assertion.  json_out_add_splice additionally ignores
 * json_out_member_direct()'s return (json_out.c:335): once mkroom() is
 * fixed to return NULL, that is memcpy(NULL, p, len).
 *
 * Allocation failure is simulated with tal_set_backend (resize_fn
 * always fails, error_fn returns instead of aborting).
 *
 * Currently fails (heap overflow / assertion abort); must pass after
 * repair.
 */
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/json_out/json_out.c>
#include <ccan/tal/tal.h>
#include <ccan/tap/tap.h>

static void ignoring_error(const char *msg)
{
	(void)msg;
}

static void *failing_resize(void *p, size_t size)
{
	(void)p;
	(void)size;
	return NULL;
}

static void restore_backend(void)
{
	tal_set_backend(malloc, realloc, free, (void (*)(const char *))abort);
}

int main(void)
{
	struct json_out *jout, *src;
	char big[1000];
	char *p;
	bool ok;

	alarm(10);
	plan_tests(4);

	memset(big, 'x', sizeof(big));
	big[sizeof(big) - 1] = '\0';

	/* json_out_add() must return false when tal_resize() fails. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	tal_set_backend(NULL, failing_resize, NULL, ignoring_error);
	ok = json_out_add(jout, "f", true, "%s", big);
	restore_backend();
	ok1(!ok);
	tal_free(jout);

	/* json_out_member_direct() must return NULL. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	tal_set_backend(NULL, failing_resize, NULL, ignoring_error);
	p = json_out_member_direct(jout, "f", 1000);
	restore_backend();
	ok1(p == NULL);
	tal_free(jout);

	/* json_out_direct() must return NULL. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	tal_set_backend(NULL, failing_resize, NULL, ignoring_error);
	p = json_out_direct(jout, 1000);
	restore_backend();
	ok1(p == NULL);
	tal_free(jout);

	/* json_out_add_splice() must return false. */
	src = json_out_new(NULL);
	json_out_start(src, NULL, '{');
	json_out_addstr(src, "x", "hello");
	json_out_end(src, '}');
	json_out_finished(src);

	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	memset(json_out_direct(jout, 50), ' ', 50);
	tal_set_backend(NULL, failing_resize, NULL, ignoring_error);
	ok = json_out_add_splice(jout, "inner", src);
	restore_backend();
	ok1(!ok);
	tal_free(jout);
	tal_free(src);

	return exit_status();
}
