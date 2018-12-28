#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdlib.h>

/* const args in callbacks should be OK. */

static void _register_callback(void (*cb)(void *arg), void *arg)
{
	(void)cb;
	(void)arg;
}

#define register_callback(cb, arg)				\
	_register_callback(typesafe_cb(void, void *, (cb), (arg)), (arg))

static void _register_callback_pre(void (*cb)(int x, void *arg), void *arg)
{
	(void)cb;
	(void)arg;
}

#define register_callback_pre(cb, arg)					\
	_register_callback_pre(typesafe_cb_preargs(void, void *, (cb), (arg), int), (arg))

static void _register_callback_post(void (*cb)(void *arg, int x), void *arg)
{
	(void)cb;
	(void)arg;
}

#define register_callback_post(cb, arg)					\
	_register_callback_post(typesafe_cb_postargs(void, void *, (cb), (arg), int), (arg))

struct undefined;

static void my_callback(struct undefined *undef)
{
	(void)undef;
}

static void my_callback_pre(int x, struct undefined *undef)
{
	(void)x;
	(void)undef;
}

static void my_callback_post(struct undefined *undef, int x)
{
	(void)x;
	(void)undef;
}

int main(void)
{
	struct undefined *handle = NULL;
	void (*cb)(struct undefined *undef) = my_callback;
	void (*pre)(int x, struct undefined *undef) = my_callback_pre;
	void (*post)(struct undefined *undef, int x) = my_callback_post;

	register_callback(cb, handle);
	register_callback_pre(pre, handle);
	register_callback_post(post, handle);
	return 0;
}
