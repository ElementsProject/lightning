#include <ccan/tcon/tcon.h>
#include <stdlib.h>

struct container {
	void *p;
};

int main(void)
{
	TCON_WRAP(struct container, int *canary) icon;
#ifdef FAIL
	char *
#else
	int *
#endif
		x = NULL;

	tcon_unwrap(tcon_check(&icon, canary, x))->p = x;
	return 0;
}
