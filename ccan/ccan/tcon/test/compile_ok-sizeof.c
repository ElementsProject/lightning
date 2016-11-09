#include <ccan/tcon/tcon.h>
#include <ccan/build_assert/build_assert.h>
#include <stdlib.h>

struct container {
	void *p;
};

struct int_container {
	struct container raw;
	TCON(int tc);
};

struct charp_and_int_container {
	struct container raw;
	TCON(int tc1; char *tc2);
};

int main(void)
{
	struct int_container icon;
	struct charp_and_int_container cicon;
	TCON_WRAP(struct container, int tc) iconw;
	TCON_WRAP(struct container, int tc1; char *tc2) ciconw;

	BUILD_ASSERT(tcon_sizeof(&icon, tc) == sizeof(int));
	BUILD_ASSERT(tcon_sizeof(&cicon, tc1) == sizeof(int));
	BUILD_ASSERT(tcon_sizeof(&cicon, tc2) == sizeof(char *));

	BUILD_ASSERT(tcon_sizeof(&iconw, tc) == sizeof(int));
	BUILD_ASSERT(tcon_sizeof(&ciconw, tc1) == sizeof(int));
	BUILD_ASSERT(tcon_sizeof(&ciconw, tc2) == sizeof(char *));

	return 0;
}
