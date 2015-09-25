#include <ccan/tcon/tcon.h>
#include <stdlib.h>

struct container {
	void *p;
};

struct int_container {
	struct container raw;
	TCON(int *canary);
};

int main(int argc, char *argv[])
{
	struct int_container icon;
#ifdef FAIL
	char *
#else
	int *
#endif
		x = NULL;

	tcon_check(&icon, canary, x)->raw.p = x;
	return 0;
}
