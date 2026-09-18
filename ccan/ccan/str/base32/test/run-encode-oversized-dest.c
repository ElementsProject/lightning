/* Auditor-added regression test (temporary) for audit finding F1:
 * base32.h documents "@destsize: the max size of the string" and
 * "Returns true if the string, including terminator, fits in @destsize",
 * but base32_encode() requires destsize to be exactly
 * base32_str_size(bufsize) and returns false for larger buffers.
 * This test encodes the documented contract; it FAILS against the
 * current implementation and must PASS after repair. */
#include <ccan/str/base32/base32.h>
/* Include the C files directly. */
#include <ccan/str/base32/base32.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
	char dest[100];

	alarm(10);
	plan_tests(6);

	memset(dest, 0xAA, sizeof(dest));
	/* 9-byte encoding of "f" fits in a 100-byte dest. */
	ok1(base32_encode("f", 1, dest, sizeof(dest)));
	ok1(strcmp(dest, "MY======") == 0);

	memset(dest, 0xAA, sizeof(dest));
	/* One extra byte of room must also be fine. */
	ok1(base32_encode("fo", 2, dest, base32_str_size(2) + 1));
	ok1(strcmp(dest, "MZXQ====") == 0);

	memset(dest, 0xAA, sizeof(dest));
	/* Empty input with room to spare. */
	ok1(base32_encode("", 0, dest, sizeof(dest)));
	ok1(dest[0] == '\0');

	return exit_status();
}
