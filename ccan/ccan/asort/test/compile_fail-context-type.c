#include <ccan/asort/asort.h>
#include <ccan/asort/asort.c>

static int cmp(char *const *a UNNEEDED, char *const *b UNNEEDED, int *flag UNNEEDED)
{
	return 0;
}

int main(int argc, char **argv)
{
#ifdef FAIL
#if HAVE_TYPEOF && HAVE_BUILTIN_CHOOSE_EXPR && HAVE_BUILTIN_TYPES_COMPATIBLE_P
	char flag;
#else
#error "Unfortunately we don't fail if no typecheck_cb support."
#endif
#else
	int flag;
#endif
	asort(argv+1, argc-1, cmp, &flag);
	return 0;
}
