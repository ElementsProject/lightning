#include <ccan/tcon/tcon.h>
#include <stdlib.h>

struct container {
	void *p;
};

struct void_container {
	struct container raw;
	TCON(void *canary);
};

int main(int argc, char *argv[])
{
	struct void_container vcon;
	TCON_WRAP(struct container, void *canary) vconw;

	(void)argc;
	tcon_check(&vcon, canary, NULL)->raw.p = NULL;
	tcon_check(&vcon, canary, argv[0])->raw.p = NULL;
	tcon_check(&vcon, canary, main)->raw.p = NULL;

	tcon_unwrap(tcon_check(&vconw, canary, NULL))->p = NULL;
	tcon_unwrap(tcon_check(&vconw, canary, argv[0]))->p = NULL;
	tcon_unwrap(tcon_check(&vconw, canary, main))->p = NULL;

	return 0;
}
