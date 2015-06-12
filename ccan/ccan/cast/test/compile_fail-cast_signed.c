#include <ccan/cast/cast.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	unsigned char *uc;
#ifdef FAIL
	int
#else
	char
#endif
		*p = NULL;

	uc = cast_signed(unsigned char *, p);
	(void) uc; /* Suppress unused-but-set-variable warning. */
	return 0;
}
