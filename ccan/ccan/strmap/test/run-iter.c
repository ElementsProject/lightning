/* Tests for strmap_iter_first/strmap_iter_next and the non-recursive
 * strmap_clear_: order must match strmap_iterate (checked against
 * sorted order by run-order.c), and deep trees must not crash.
 * Compiled with varying STRMAP_NUM_ITER_PARENTS to exercise the
 * slow (successor re-descent) path. */
#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <unistd.h>

/* A staircase of 8 splits per byte gives a chain of depth ~N. */
#define NDEEP 3000

static STRMAP(char *) map;
static const char *members[600];
static unsigned int nmembers;

static bool grab(const char *member, char *value, void *p)
{
	(void)value;
	(void)p;
	members[nmembers++] = member;
	return true;
}

int main(void)
{
	unsigned int i, n;
	const char *m;
	char *v;
	struct strmap_iter it;
	bool order_ok, slow_seen;

	alarm(60);
	plan_tests(7);

	/* Empty map. */
	strmap_init(&map);
	ok1(strmap_iter_first(&it, &map, &v) == NULL);

	/* Random-ish set (xorshift), with shared prefixes. */
	{
		static char buf[500][16];
		static char val[500];
		uint64_t r = 0x0fedcba987654321ULL;
		for (i = 0; i < 500; i++) {
			unsigned int j, len;
			r ^= r << 13; r ^= r >> 7; r ^= r << 17;
			len = r % 12 + 1;
			for (j = 0; j < len; j++) {
				r ^= r << 13; r ^= r >> 7; r ^= r << 17;
				buf[i][j] = 'a' + (r % 26);
			}
			buf[i][len] = '\0';
			if (i % 3 == 0 && i > 0)
				buf[i][0] = buf[i-1][0];
			val[i] = (char)i;
			strmap_add(&map, buf[i], &val[i]);
		}
	}

	/* Reference order via the cursor-based iterate. */
	nmembers = 0;
	strmap_iterate(&map, grab, NULL);
	n = nmembers;

	order_ok = true;
	slow_seen = false;
	i = 0;
	for (m = strmap_iter_first(&it, &map, &v);
	     m;
	     m = strmap_iter_next(&it, &map, m, &v)) {
		if (it.slow_mode)
			slow_seen = true;
		if (i >= n || strcmp(m, members[i]) != 0)
			order_ok = false;
		i++;
	}
	ok1(i == n);
	ok1(order_ok);
	/* With the default 16 parents this map should not need the
	 * slow path; with a tiny override it must have been used. */
	if (STRMAP_NUM_ITER_PARENTS >= 16)
		ok1(!slow_seen);
	else
		ok1(slow_seen);

	/* Check values track members: iterate and verify each value. */
	{
		bool vals_ok = true;
		for (m = strmap_iter_first(&it, &map, &v);
		     m;
		     m = strmap_iter_next(&it, &map, m, &v)) {
			if (strmap_get(&map, m) != v)
				vals_ok = false;
		}
		ok1(vals_ok);
	}
	strmap_clear(&map);
	ok1(strmap_empty(&map));

	/* Deep staircase: iterate and clear without stack overflow. */
	{
		static char deep[NDEEP][400];
		static char dval;
		unsigned int j;
		for (i = 0; i < NDEEP; i++) {
			unsigned int len = i / 8 + 1;
			for (j = 0; j < len - 1; j++)
				deep[i][j] = '\xff';
			if (i % 8 == 0)
				deep[i][len-1] = 0x01;
			else
				deep[i][len-1] = (char)(unsigned char)(0xff << (i % 8));
			deep[i][len] = '\0';
			strmap_add(&map, deep[i], &dval);
		}
		n = 0;
		order_ok = true;
		for (m = strmap_iter_first(&it, &map, &v);
		     m;
		     m = strmap_iter_next(&it, &map, m, &v)) {
			if (n > 0 && strcmp(m, members[0]) <= 0)
				order_ok = false;
			members[0] = m;
			n++;
		}
		strmap_clear(&map);
		ok1(n == NDEEP && order_ok && strmap_empty(&map));
	}

	return exit_status();
}
