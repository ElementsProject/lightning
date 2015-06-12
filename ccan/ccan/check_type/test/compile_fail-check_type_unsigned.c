#include <ccan/check_type/check_type.h>

int main(int argc, char *argv[])
{
#ifdef FAIL
#if HAVE_TYPEOF
	check_type(argc, unsigned int);
#else
	/* This doesn't work without typeof, so just fail */
#error "Fail without typeof"
#endif
#endif
	return 0;
}
