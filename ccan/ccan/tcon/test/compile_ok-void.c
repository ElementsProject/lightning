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

	tcon_check(&vcon, canary, NULL)->raw.p = NULL;
	tcon_check(&vcon, canary, argv[0])->raw.p = NULL;
	tcon_check(&vcon, canary, main)->raw.p = NULL;
	return 0;
}
