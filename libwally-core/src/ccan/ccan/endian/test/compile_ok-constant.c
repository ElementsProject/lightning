#include <ccan/endian/endian.h>

struct foo {
	char one[BSWAP_16(0xFF00)];
	char two[BSWAP_32(0xFF000000)];
	char three[BSWAP_64(0xFF00000000000000ULL)];
};

int main(void)
{
	return 0;
}
