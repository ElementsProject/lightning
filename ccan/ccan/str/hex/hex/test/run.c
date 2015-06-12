#include <ccan/str/hex/hex.h>
/* Include the C files directly. */
#include <ccan/str/hex/hex.c>
#include <ccan/tap/tap.h>
#include <string.h>

int main(void)
{
	const char teststr[] = "0123456789abcdefABCDEF";
	const char bad_teststr[] = "0123456789abcdefABCDEF1O";
	const unsigned char testdata[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
					   0xcd, 0xef, 0xAB, 0xCD, 0xEF };
	unsigned char data[11];
	char str[23];
	size_t i;
	
	plan_tests(10 + sizeof(str));
	
	ok1(hex_str_size(sizeof(testdata)) == sizeof(teststr));
	/* This gives right result with or without nul included */
	ok1(hex_data_size(strlen(teststr)) == sizeof(testdata));
	ok1(hex_data_size(sizeof(teststr)) == sizeof(testdata));

	ok1(hex_decode(teststr, strlen(teststr), data, sizeof(data)));
	ok1(memcmp(data, testdata, sizeof(testdata)) == 0);
	ok1(hex_encode(testdata, sizeof(testdata), str, sizeof(str)));
	ok1(strcmp(str, "0123456789abcdefabcdef") == 0);

	/* Bad char */
	ok1(!hex_decode(bad_teststr, strlen(bad_teststr), data, sizeof(data)));
	/* Bad hex string len */
	ok1(!hex_decode(teststr, strlen(teststr) - 1, data, sizeof(data)));
	/* Bad buffer len */
	ok1(!hex_decode(teststr, strlen(teststr), data, sizeof(data) - 1));

	/* Bad deststring size. */
	for (i = 1; i <= sizeof(str); i++)
		ok1(!hex_encode(testdata, sizeof(testdata), str, sizeof(str)-i));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
