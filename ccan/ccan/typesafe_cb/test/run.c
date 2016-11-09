#include <ccan/typesafe_cb/typesafe_cb.h>
#include <string.h>
#include <stdint.h>
#include <ccan/tap/tap.h>

static char dummy = 0;

/* The example usage. */
static void _set_some_value(void *val)
{
	ok1(val == &dummy);
}

#define set_some_value(expr)						\
	_set_some_value(typesafe_cb_cast(void *, unsigned long, (expr)))

static void _callback_onearg(void (*fn)(void *arg), void *arg)
{
	fn(arg);
}

static void _callback_preargs(void (*fn)(int a, int b, void *arg), void *arg)
{
	fn(1, 2, arg);
}

static void _callback_postargs(void (*fn)(void *arg, int a, int b), void *arg)
{
	fn(arg, 1, 2);
}

#define callback_onearg(cb, arg)					\
	_callback_onearg(typesafe_cb(void, void *, (cb), (arg)), (arg))

#define callback_preargs(cb, arg)					\
	_callback_preargs(typesafe_cb_preargs(void, void *, (cb), (arg), int, int), (arg))

#define callback_postargs(cb, arg)					\
	_callback_postargs(typesafe_cb_postargs(void, void *, (cb), (arg), int, int), (arg))

static void my_callback_onearg(char *p)
{
	ok1(strcmp(p, "hello world") == 0);
}

static void my_callback_preargs(int a, int b, char *p)
{
	ok1(a == 1);
	ok1(b == 2);
	ok1(strcmp(p, "hello world") == 0);
}

static void my_callback_postargs(char *p, int a, int b)
{
	ok1(a == 1);
	ok1(b == 2);
	ok1(strcmp(p, "hello world") == 0);
}

/* This is simply a compile test; we promised typesafe_cb_cast can be in a
 * static initializer. */
struct callback_onearg
{
	void (*fn)(void *arg);
	const void *arg;
};

struct callback_onearg cb_onearg
= { typesafe_cb(void, void *, my_callback_onearg, (char *)(intptr_t)"hello world"),
    "hello world" };

struct callback_preargs
{
	void (*fn)(int a, int b, void *arg);
	const void *arg;
};

struct callback_preargs cb_preargs
= { typesafe_cb_preargs(void, void *, my_callback_preargs,
			(char *)(intptr_t)"hi", int, int), "hi" };

struct callback_postargs
{
	void (*fn)(void *arg, int a, int b);
	const void *arg;
};

struct callback_postargs cb_postargs
= { typesafe_cb_postargs(void, void *, my_callback_postargs, 
			 (char *)(intptr_t)"hi", int, int), "hi" };

int main(void)
{
	void *p = &dummy;
	unsigned long l = (unsigned long)p;
	char str[] = "hello world";

	plan_tests(2 + 1 + 3 + 3);
	set_some_value(p);
	set_some_value(l);

	callback_onearg(my_callback_onearg, str);

	callback_preargs(my_callback_preargs, str);

	callback_postargs(my_callback_postargs, str);

	return exit_status();
}
