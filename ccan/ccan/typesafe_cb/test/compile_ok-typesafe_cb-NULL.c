#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdlib.h>

/* NULL args for callback function should be OK for normal and _def. */

static void _register_callback(void (*cb)(const void *arg), const void *arg)
{
	(void)cb;
	(void)arg;
}

#define register_callback(cb, arg)				\
	_register_callback(typesafe_cb(void, const void *, (cb), (arg)), (arg))

int main(void)
{
	register_callback(NULL, "hello world");
	return 0;
}
