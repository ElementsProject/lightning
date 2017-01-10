#include <ccan/str/str.h>

int main(void)
{
	static char str[STR_MAX_CHARS(int)];

	return str[0] ? 0 : 1;
}
