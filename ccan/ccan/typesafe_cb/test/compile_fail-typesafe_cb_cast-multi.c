#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdlib.h>

struct foo {
	int x;
};

struct bar {
	int x;
};

struct baz {
	int x;
};

struct any {
	int x;
};

struct other {
	int x;
};

static void take_any(struct any *any)
{
	(void)any;
}

int main(void)
{
#ifdef FAIL
	struct other
#if !HAVE_TYPEOF||!HAVE_BUILTIN_CHOOSE_EXPR||!HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if typesafe_cb_cast is a noop."
#endif
#else
	struct foo
#endif
		*arg = NULL;
	take_any(typesafe_cb_cast3(struct any *,
				   struct foo *, struct bar *, struct baz *,
				   arg));
	return 0;
}
