#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>

static void _set_some_value(void *val)
{
}

#define set_some_value(expr)						\
	_set_some_value(typesafe_cb_cast(void *, long, (expr)))

int main(int argc, char *argv[])
{
#ifdef FAIL
	bool x = 0;
#if !HAVE_TYPEOF||!HAVE_BUILTIN_CHOOSE_EXPR||!HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if typesafe_cb_cast is a noop."
#endif
#else
	long x = 0;
#endif
	set_some_value(x);
	return 0;
}
