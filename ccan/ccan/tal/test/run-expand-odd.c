#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>
#include <stdint.h>
#include <string.h>

/* Expanding an object whose bytelen is not a multiple of the element
 * size must not write past the (rounded) allocation. */
int main(void)
{
	char *c;
	uint16_t *p, v = 0x4141;

	plan_tests(5);

	c = tal_arr(NULL, char, 5);
	memset(c, 0, 5);
	p = (uint16_t *)c;
	ok1(tal_expand(&p, &v, 1));
	/* Exact length: 5 + 2 == 7 bytes, preserving the odd byte. */
	ok1(tal_bytelen(p) == 7);
	/* tal_count() grows by exactly count. */
	ok1(tal_count(p) == 3);
	ok1(memcmp(p, "\0\0\0\0\0", 5) == 0);
	c = (char *)p;
	ok1(c[5] == 0x41 && c[6] == 0x41);

	tal_free(c);
	tal_cleanup();
	return exit_status();
}
