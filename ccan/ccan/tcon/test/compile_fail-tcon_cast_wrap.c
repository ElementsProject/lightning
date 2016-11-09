#include <ccan/tcon/tcon.h>
#include <stdlib.h>

struct container {
	void *p;
};

int main(void)
{
	TCON_WRAP(struct container,
		  int *tc1; char *tc2) icon;
#ifdef FAIL
#if !HAVE_TYPEOF
#error We cannot detect type problems without HAVE_TYPEOF
#endif
	char *
#else
	int *
#endif
		x;

	tcon_unwrap(&icon)->p = NULL;
	x = tcon_cast(&icon, tc1, tcon_unwrap(&icon)->p);
	return x != NULL ? 0 : 1;
}
