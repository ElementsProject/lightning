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

int main(int argc, char *argv[])
{
	struct int_container icon;
	struct charp_and_int_container cicon;
	TCON_WRAP(struct container, int tc) iconw;
	TCON_WRAP(struct container, int tc1; char *tc2) ciconw;

	(void)argc;
	tcon_check(&icon, tc, 7)->raw.p = NULL;
	tcon_check(&cicon, tc1, 7)->raw.p = argv[0];
	tcon_check(&cicon, tc2, argv[0])->raw.p = argv[0];

	tcon_unwrap(tcon_check(&iconw, tc, 7))->p = NULL;
	tcon_unwrap(tcon_check(&ciconw, tc1, 7))->p = argv[0];
	tcon_unwrap(tcon_check(&ciconw, tc2, argv[0]))->p = argv[0];

	BUILD_ASSERT(sizeof(iconw) == sizeof(struct container));
	BUILD_ASSERT(sizeof(ciconw) == sizeof(struct container));

	return 0;
}
