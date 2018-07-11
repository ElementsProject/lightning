#include <ccan/utf8/utf8.h>
/* Include the C files directly. */
#include <ccan/utf8/utf8.c>
#include <ccan/tap/tap.h>
#include <assert.h>

static bool utf8_check(const char *src, size_t len)
{
	bool decoded = false;
	struct utf8_state utf8_state = UTF8_STATE_INIT;
	size_t i;

	for (i = 0; i < len; i++) {
		decoded = utf8_decode(&utf8_state, src[i]);
		if (decoded) {
			if (errno != 0)
				return false;
		}
	}
	if (!decoded)
		return false;
	return true;
}

int main(int argc, char **argv)
{
	int i;
	char dest[UTF8_MAX_LEN];
	
	plan_tests(0x10FFFF - (0xDFFF - 0xD7FF + 2));

	for (i = 1; i < 0x10FFFF; i++) {
		int len;
		if (i >= 0xD7FF && i <= 0xDFFF)
			continue;
		len = utf8_encode(i, dest);
		assert(len != 0);
		ok1(utf8_check(dest, len));
	}

	return exit_status();
}
