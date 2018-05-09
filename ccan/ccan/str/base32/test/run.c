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

	/* Test vectors from RFC */
	test("", "");
	test("f", "MY======");
	test("fo", "MZXQ====");
	test("foo", "MZXW6===");
	test("foob", "MZXW6YQ=");
	test("fooba", "MZXW6YTB");
	test("r", "OI======");
	test("foobar", "MZXW6YTBOI======");

	/* This exits depending on whether all tests passed */
	return exit_status();
}
