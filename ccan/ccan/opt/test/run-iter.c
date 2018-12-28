#include <ccan/tap/tap.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include "utils.h"
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>

/* Test iterators. */
int main(void)
{
	unsigned j, i, len = 0;
	const char *p;

	plan_tests(37 * 2);
	for (j = 0; j < 2; j ++) {
		reset_options();
		/* Giving subtable a title makes an extra entry! */
		opt_register_table(subtables, j == 0 ? NULL : "subtable");

		p = first_lopt(&i, &len);
		ok1(i == j + 0);
		ok1(len == 3);
		ok1(strncmp(p, "jjj", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 0);
		ok1(len == 3);
		ok1(strncmp(p, "lll", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 1);
		ok1(len == 3);
		ok1(strncmp(p, "mmm", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 5);
		ok1(len == 3);
		ok1(strncmp(p, "ddd", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 6);
		ok1(len == 3);
		ok1(strncmp(p, "eee", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 7);
		ok1(len == 3);
		ok1(strncmp(p, "ggg", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(i == j + 8);
		ok1(len == 3);
		ok1(strncmp(p, "hhh", len) == 0);
		p = next_lopt(p, &i, &len);
		ok1(!p);

		p = first_sopt(&i);
		ok1(i == j + 0);
		ok1(*p == 'j');
		p = next_sopt(p, &i);
		ok1(i == j + 0);
		ok1(*p == 'l');
		p = next_sopt(p, &i);
		ok1(i == j + 1);
		ok1(*p == 'm');
		p = next_sopt(p, &i);
		ok1(i == j + 2);
		ok1(*p == 'a');
		p = next_sopt(p, &i);
		ok1(i == j + 3);
		ok1(*p == 'b');
		p = next_sopt(p, &i);
		ok1(i == j + 7);
		ok1(*p == 'g');
		p = next_sopt(p, &i);
		ok1(i == j + 8);
		ok1(*p == 'h');
		p = next_sopt(p, &i);
		ok1(!p);
	}

	return exit_status();
}
