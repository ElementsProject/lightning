#include <ccan/check_type/check_type.h>

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
#ifdef FAIL
	check_type(argc, char);
#endif
	return 0;
}
