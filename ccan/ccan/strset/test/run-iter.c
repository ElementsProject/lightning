/* Tests for strset_iter_first/strset_iter_next: order must match
 * strset_iterate (itself checked against sorted order by run-order.c),
 * and deep trees must not crash (see audit-findings/strset.md F1).
 * Compiled with varying STRSET_NUM_ITER_PARENTS to exercise the
 * slow_mode (successor re-descent) path. */
#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <unistd.h>

/* A staircase of 8 splits per byte gives a chain of depth ~N. */
#define NDEEP 3000

static struct strset set;
static const char *members[NDEEP + 3];
static unsigned int nmembers;

static bool grab(const char *member, void *p)
{
	(void)p;
	members[nmembers++] = member;
	return true;
}

int main(void)
{
	unsigned int i, n;
	const char *m;
	struct strset_iter it;
	bool order_ok, slow_seen;

	alarm(60);
	plan_tests(7);

	/* Empty set. */
	strset_init(&set);
	ok1(strset_iter_first(&it, &set) == NULL);

	/* Just the empty string. */
	strset_add(&set, "");
	m = strset_iter_first(&it, &set);
	ok1(m != NULL && m[0] == '\0');
	ok1(strset_iter_next(&it, &set, m) == NULL);
	strset_clear(&set);

	/* Random-ish set (xorshift), including "" and shared prefixes. */
	strset_init(&set);
	{
		static char buf[600][16];
		uint64_t r = 0x123456789abcdef0ULL;
		strset_add(&set, "");
		for (i = 0; i < 500; i++) {
			unsigned int j, len;
			r ^= r << 13; r ^= r >> 7; r ^= r << 17;
			len = r % 12 + 1;
			for (j = 0; j < len; j++) {
				r ^= r << 13; r ^= r >> 7; r ^= r << 17;
				buf[i][j] = 'a' + (r % 26);
			}
			buf[i][len] = '\0';
			/* Force prefix collisions. */
			if (i % 3 == 0 && i > 0)
				buf[i][0] = buf[i-1][0];
			strset_add(&set, buf[i]);
		}
	}

	/* Reference order via the existing (recursive) iterate. */
	nmembers = 0;
	strset_iterate(&set, grab, NULL);
	n = nmembers;

	order_ok = true;
	slow_seen = false;
	i = 0;
	for (m = strset_iter_first(&it, &set); m; m = strset_iter_next(&it, &set, m)) {
		if (it.slow_mode)
			slow_seen = true;
		if (i >= n || strcmp(m, members[i]) != 0)
			order_ok = false;
		i++;
	}
	ok1(i == n);
	ok1(order_ok);
	/* With the default 16 parents this set should not need the
	 * slow_mode path; with a tiny override it must have been used. */
	if (STRSET_NUM_ITER_PARENTS >= 16)
		ok1(!slow_seen);
	else
		ok1(slow_seen);
	strset_clear(&set);

	/* Deep staircase: iterate without stack overflow, in order. */
	strset_init(&set);
	{
		static char deep[NDEEP][400];
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
			strset_add(&set, deep[i]);
		}
	}

	n = 0;
	order_ok = true;
	for (m = strset_iter_first(&it, &set); m; m = strset_iter_next(&it, &set, m)) {
		if (n > 0 && strcmp(m, members[0]) <= 0)
			order_ok = false;
		members[0] = m;
		n++;
	}
	ok1(n == NDEEP && order_ok);
	strset_clear(&set);

	return exit_status();
}
