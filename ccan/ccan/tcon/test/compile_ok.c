#include <ccan/tcon/tcon.h>
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

	tcon_check(&icon, tc, 7)->raw.p = NULL;
	tcon_check(&cicon, tc1, 7)->raw.p = argv[0];
	tcon_check(&cicon, tc2, argv[0])->raw.p = argv[0];
	return 0;
}
