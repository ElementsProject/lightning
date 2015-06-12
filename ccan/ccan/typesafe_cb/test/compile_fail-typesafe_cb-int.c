#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdlib.h>

void _callback(void (*fn)(void *arg), void *arg);
void _callback(void (*fn)(void *arg), void *arg)
{
	fn(arg);
}

/* Callback is set up to warn if arg isn't a pointer (since it won't
 * pass cleanly to _callback's second arg. */
#define callback(fn, arg)						\
	_callback(typesafe_cb(void, (fn), (arg)), (arg))

void my_callback(int something);
void my_callback(int something)
{
}

int main(int argc, char *argv[])
{
#ifdef FAIL
	/* This fails due to arg, not due to cast. */
	callback(my_callback, 100);
#endif
	return 0;
}
