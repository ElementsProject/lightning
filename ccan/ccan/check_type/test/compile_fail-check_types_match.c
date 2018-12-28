#include <ccan/check_type/check_type.h>

int main(int argc, char *argv[])
{
	unsigned char x = argc;
	(void)argv;
#ifdef FAIL
	check_types_match(argc, x);
#endif
	return x;
}
