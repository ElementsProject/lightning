#include "config.h"

#include <assert.h>

#include <ccan/mem/mem.h>
#include <ccan/tap/tap.h>

#define SWAPSIZE	12

int main(void)
{
	char haystack1[] = "abcd\0efgh";
	char haystack2[] = "ab\0ab\0ab\0ab";
	char needle1[] = "ab";
	char needle2[] = "d\0e";
	char scan1[] = "aaaab";
	char scan2[] = "\0\0\0b";
	char tmp1[SWAPSIZE], tmp2[SWAPSIZE];

	/* This is how many tests you plan to run */
	plan_tests(65);

	ok1(memmem(haystack1, sizeof(haystack1), needle1, 2) == haystack1);
	ok1(memmem(haystack1, sizeof(haystack1), needle1, 3) == NULL);
	ok1(memmem(haystack1, sizeof(haystack1), needle2, 3) == (haystack1 + 3));

	ok1(memmem(haystack2, sizeof(haystack2), needle1, sizeof(needle1))
	    == haystack2);
	ok1(memmem(haystack2, sizeof(haystack2), needle2, 3) == NULL);

	ok1(memrchr(haystack1, 'a', sizeof(haystack1)) == haystack1);
	ok1(memrchr(haystack1, 'b', sizeof(haystack1)) == haystack1 + 1);
	ok1(memrchr(haystack1, 'c', sizeof(haystack1)) == haystack1 + 2);
	ok1(memrchr(haystack1, 'd', sizeof(haystack1)) == haystack1 + 3);
	ok1(memrchr(haystack1, 'e', sizeof(haystack1)) == haystack1 + 5);
	ok1(memrchr(haystack1, 'f', sizeof(haystack1)) == haystack1 + 6);
	ok1(memrchr(haystack1, 'g', sizeof(haystack1)) == haystack1 + 7);
	ok1(memrchr(haystack1, 'h', sizeof(haystack1)) == haystack1 + 8);
	ok1(memrchr(haystack1, '\0', sizeof(haystack1)) == haystack1 + 9);
	ok1(memrchr(haystack1, 'i', sizeof(haystack1)) == NULL);

	ok1(memrchr(haystack2, 'a', sizeof(haystack2)) == haystack2 + 9);
	ok1(memrchr(haystack2, 'b', sizeof(haystack2)) == haystack2 + 10);
	ok1(memrchr(haystack2, '\0', sizeof(haystack2)) == haystack2 + 11);

	ok1(memrchr(needle1, '\0', 2) == NULL);

#define S(x) (x), sizeof(x) - 1
	ok1(mempbrkm(S(haystack1), S("\0efgh")) == haystack1 + 4);
	ok1(mempbrkm(S(haystack1), S("jklmn")) == NULL);
	ok1(mempbrkm(S(haystack1), S("sd\0a")) == haystack1 + 0);

	ok1(mempbrk(haystack1, sizeof(haystack1), "bcd\0a") == haystack1 + 1);
	ok1(mempbrk(haystack1, sizeof(haystack1), "\0") == NULL);

	ok1(memcchr(scan1, 'a', sizeof(scan1)) == scan1 + 4);
	ok1(memcchr(scan1, 'b', sizeof(scan1)) == scan1);
	ok1(memcchr(scan2, '\0', sizeof(scan2)) == scan2 + 3);
	ok1(memcchr(scan2, '\0', sizeof(scan2) - 2) == NULL);

	ok1(memeq(haystack1, sizeof(haystack1), haystack1, sizeof(haystack1)));
	ok1(!memeq(haystack1, sizeof(haystack1), haystack2, sizeof(haystack2)));

	ok1(memeqstr(scan1, sizeof(scan1) - 1, scan1));
	ok1(!memeqstr(scan1, sizeof(scan1), scan1));
	ok1(!memeqstr(scan1, sizeof(scan1), "aaaa"));

	ok1(memstarts(S("a\0bcdef"), S("a\0bc")));
	ok1(!memstarts(S("a\0bcdef"), S("a\0bcG")));
	ok1(!memstarts(S("a\0bcdef"), S("a\0bcdefg")));

	ok1(memstarts_str(scan1, sizeof(scan1), scan1));
	ok1(!memstarts_str(scan1, sizeof(scan1), "ab"));

	ok1(memends(S("abcdef"), S("abcdef")));
	ok1(!memends(S("abcdef"), S("abcdefg")));
	ok1(!memends(S("a\0bcdef"), S("a\0b")));
	ok1(memends(S("a\0bcdef"), S("ef")));

	ok1(memends_str(S("abcdef"), "abcdef"));
	ok1(!memends_str(S("abcde\0f"), "d\0f"));
	ok1(!memends_str(S("a\0bcdef"), "a"));
	ok1(memends_str(S("a\0bcdef"), "ef"));

	ok1(!memoverlaps(haystack1, sizeof(haystack1),
			 haystack2, sizeof(haystack2)));
	ok1(!memoverlaps(haystack2, sizeof(haystack2),
			 haystack1, sizeof(haystack1)));
	ok1(memoverlaps(haystack1, sizeof(haystack1), haystack1, 1));
	ok1(memoverlaps(haystack1, 1, haystack1, sizeof(haystack1)));
	ok1(memoverlaps(haystack1, sizeof(haystack1),
			haystack1 + sizeof(haystack1) - 1, 1));
	ok1(memoverlaps(haystack1 + sizeof(haystack1) - 1, 1,
			haystack1, sizeof(haystack1)));
	ok1(!memoverlaps(haystack1, sizeof(haystack1),
			 haystack1 + sizeof(haystack1), 1));
	ok1(!memoverlaps(haystack1 + sizeof(haystack1), 1,
			 haystack1, sizeof(haystack1)));
	ok1(!memoverlaps(haystack1, sizeof(haystack1), haystack1 - 1, 1));
	ok1(!memoverlaps(haystack1 - 1, 1, haystack1, sizeof(haystack1)));
	ok1(memoverlaps(haystack1, 5, haystack1 + 4, 7));
	ok1(!memoverlaps(haystack1, 5, haystack1 + 5, 6));
	ok1(memoverlaps(haystack1 + 4, 7, haystack1, 5));
	ok1(!memoverlaps(haystack1 + 5, 6, haystack1, 5));

	assert(sizeof(haystack1) <= SWAPSIZE);
	assert(sizeof(haystack2) <= SWAPSIZE);
	memset(tmp1, 0, sizeof(tmp1));
	memset(tmp2, 0, sizeof(tmp2));
	memcpy(tmp1, haystack1, sizeof(haystack1));
	memcpy(tmp2, haystack2, sizeof(haystack2));
	memswap(tmp1, tmp2, SWAPSIZE);
	ok1(memcmp(tmp1, haystack2, sizeof(haystack2)) == 0);
	ok1(memcmp(tmp2, haystack1, sizeof(haystack1)) == 0);

	ok1(memeqzero(NULL, 0));
	ok1(memeqzero(scan2, 3));
	ok1(!memeqzero(scan2, 4));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
