/* An unprototyped callback defeats typesafe_cb()'s check entirely:
 * void (*)() is not compatible with void (*)(int *) in the
 * __builtin_types_compatible_p sense, so the macro declines to cast,
 * and the conversion to void (*)(void *) is silently accepted (gcc and
 * clang give no diagnostic at -Wall).  This compile_ok test pins that
 * behavior (see audit-findings/typesafe_cb.md F2): callbacks must have
 * full prototypes to be checked. */
#include <ccan/typesafe_cb/typesafe_cb.h>

static void _register_callback(void (*cb)(void *arg), void *arg)
{
	(void)cb;
	(void)arg;
}

#define register_callback(cb, arg)				\
	_register_callback(typesafe_cb(void, void *, (cb), (arg)), (arg))

static void my_callback()
{
}

int main(void)
{
	int *p = (void *)0;

	/* With a prototype (eg. void my_callback(char *)), this would
	 * warn: the argument type does not match. */
	register_callback(my_callback, p);
	return 0;
}
