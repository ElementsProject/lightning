#include <ccan/str/base32/base32.h>
/* Include the C files directly. */
#include <ccan/str/base32/base32.c>
#include <ccan/tap/tap.h>

static void test(const char *data, const char *b32)
{
	char test[1000];

	ok1(base32_str_size(strlen(data)) == strlen(b32) + 1);
	ok1(base32_data_size(b32, strlen(b32)) == strlen(data));
	ok1(base32_encode(data, strlen(data), test, strlen(b32)+1));
	ok1(strcmp(test, b32) == 0);
	test[strlen(data)] = '\0';
	ok1(base32_decode(b32, strlen(b32), test, strlen(data)));
	ok1(strcmp(test, data) == 0);
}

int main(void)
{
	/* This is how many tests you plan to run */
	plan_tests(8 * 6);

	base32_chars = "abcdefghijklmnopqrstuvwxyz234567=";

	/* Test vectors from RFC, but lower-case */
	test("", "");
	test("f", "my======");
	test("fo", "mzxq====");
	test("foo", "mzxw6===");
	test("foob", "mzxw6yq=");
	test("fooba", "mzxw6ytb");
	test("r", "oi======");
	test("foobar", "mzxw6ytboi======");

	/* This exits depending on whether all tests passed */
	return exit_status();
}
