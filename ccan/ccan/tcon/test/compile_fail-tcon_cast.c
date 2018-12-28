#include <ccan/tcon/tcon.h>
#include <stdlib.h>

struct container {
	void *p;
};

struct int_and_charp_container {
	struct container raw;
	TCON(int *tc1; char *tc2);
};

int main(void)
{
	struct int_and_charp_container icon;
#ifdef FAIL
#if !HAVE_TYPEOF
#error We cannot detect type problems without HAVE_TYPEOF
#endif
	char *
#else
	int *
#endif
		x;

	icon.raw.p = NULL;
	x = tcon_cast(&icon, tc1, icon.raw.p);
	return x != NULL ? 0 : 1;
}
