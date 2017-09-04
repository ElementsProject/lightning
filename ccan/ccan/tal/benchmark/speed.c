/*
   Taken from samba/lib/talloc/testsuite.c: Unix SMB/CIFS implementation.

   local testing of talloc routines.

   Copyright (C) Andrew Tridgell 2004

     ** NOTE! The following LGPL license applies to the talloc
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include <ccan/talloc/talloc.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/err/err.h>
#include <string.h>

#define LOOPS 1024

int main(int argc, char *argv[])
{
	void *ctx;
	unsigned count;
	int i, j;
	struct timeabs tv;
	void *p1, *p2[100], *p3[100];
	bool run_talloc = true, run_tal = true, run_malloc = true;

	if (argv[1]) {
		if (strcmp(argv[1], "--talloc") == 0)
			run_tal = run_malloc = false;
		else if (strcmp(argv[1], "--tal") == 0)
			run_talloc = run_malloc = false;
		else if (strcmp(argv[1], "--malloc") == 0)
			run_talloc = run_tal = false;
		else
			errx(1, "Bad flag %s", argv[1]);
	}

	if (!run_talloc)
		goto after_talloc;

	ctx = talloc_new(NULL);
	tv = time_now();
	count = 0;
	do {
		for (i=0;i<LOOPS;i++) {
			p1 = talloc_size(ctx, LOOPS % 128);
			for (j = 0; j < 100; j++) {
				p2[j] = talloc_strdup(p1, "foo bar");
				p3[j] = talloc_size(p1, 300);
			}
			talloc_free(p1);
		}
		count += (1 + 200) * LOOPS;
	} while (time_between(time_now(), tv).ts.tv_sec < 5);

	fprintf(stderr, "talloc: %.0f ops/sec\n", count/5.0);

	talloc_free(ctx);

after_talloc:
	if (!run_tal)
		goto after_tal;

	ctx = tal(NULL, char);
	tv = time_now();
	count = 0;
	do {
		for (i=0;i<LOOPS;i++) {
			p1 = tal_arr(ctx, char, LOOPS % 128);
			for (j = 0; j < 100; j++) {
				p2[j] = tal_strdup(p1, "foo bar");
				p3[j] = tal_arr(p1, char, 300);
			}
			tal_free(p1);
		}
		count += (1 + 200) * LOOPS;
	} while (time_between(time_now(), tv).ts.tv_sec < 5);
	fprintf(stderr, "tal:    %.0f ops/sec\n", count/5.0);

	tal_free(ctx);

after_tal:
	if (!run_malloc)
		goto after_malloc;

	tv = time_now();
	count = 0;
	do {
		for (i=0;i<LOOPS;i++) {
			p1 = malloc(LOOPS % 128);
			for (j = 0; j < 100; j++) {
				p2[j] = strdup("foo bar");
				p3[j] = malloc(300);
			}
			for (j = 0; j < 100; j++) {
				free(p2[j]);
				free(p3[j]);
			}
			free(p1);
		}
		count += (1 + 200) * LOOPS;
	} while (time_between(time_now(), tv).ts.tv_sec < 5);
	fprintf(stderr, "malloc: %.0f ops/sec\n", count/5.0);

after_malloc:
	printf("success: speed\n");

	return 0;
}
