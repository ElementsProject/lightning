#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdlib.h>

/* const args in callbacks should be OK. */

static void _register_callback(void (*cb)(void *arg), void *arg)
{
}

#define register_callback(cb, arg)				\
	_register_callback(typesafe_cb(void, void *, (cb), (arg)), (arg))

static void _register_callback_pre(void (*cb)(int x, void *arg), void *arg)
{
}

#define register_callback_pre(cb, arg)					\
	_register_callback_pre(typesafe_cb_preargs(void, void *, (cb), (arg), int), (arg))

static void _register_callback_post(void (*cb)(void *arg, int x), void *arg)
{
}

#define register_callback_post(cb, arg)					\
	_register_callback_post(typesafe_cb_postargs(void, void *, (cb), (arg), int), (arg))

struct undefined;

static void my_callback(struct undefined *undef)
{
}

static void my_callback_pre(int x, struct undefined *undef)
{
}

static void my_callback_post(struct undefined *undef, int x)
{
}

int main(int argc, char *argv[])
{
	struct undefined *handle = NULL;

	register_callback(my_callback, handle);
	register_callback_pre(my_callback_pre, handle);
	register_callback_post(my_callback_post, handle);
	return 0;
}
