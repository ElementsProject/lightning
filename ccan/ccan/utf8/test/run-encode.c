#include <ccan/utf8/utf8.h>
/* Include the C files directly. */
#include <ccan/utf8/utf8.c>
#include <ccan/tap/tap.h>

int main(int argc, char **argv)
{
	int i;
	char dest[UTF8_MAX_LEN];

	plan_tests(1 + 0x10FFFF + 1);

	for (i = 0; i < 1; i++)
		ok1(utf8_encode(i, dest) == 0 && errno == ERANGE);
	for (; i <= 0x7F; i++)
		ok1(utf8_encode(i, dest) == 1);
	for (; i <= 0x7FF; i++)
		ok1(utf8_encode(i, dest) == 2);
	for (; i <= 0xD7FF; i++)
		ok1(utf8_encode(i, dest) == 3);
	for (; i <= 0xDFFF; i++)
		ok1(utf8_encode(i, dest) == 0 && errno == ERANGE);
	for (; i <= 0xFFFF; i++)
		ok1(utf8_encode(i, dest) == 3);
	for (; i <= 0x10FFFF; i++)
		ok1(utf8_encode(i, dest) == 4);
	ok1(utf8_encode(i, dest) == 0 && errno == ERANGE);

	return exit_status();
}
