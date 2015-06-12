#include <ccan/check_type/check_type.h>

int main(int argc, char *argv[])
{
	unsigned char x = argc;
#ifdef FAIL
	check_types_match(argc, x);
#endif
	return x;
}
