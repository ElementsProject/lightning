/* OpenIndiana's CC (aka suncc) has issues with constants: make sure
 * we are one! */
#include <ccan/cast/cast.h>

static char *p = cast_const(char *, (const char *)"hello");

int main(int argc, char *argv[])
{
	(void)argc;
	return p[0] == argv[0][0];
}
