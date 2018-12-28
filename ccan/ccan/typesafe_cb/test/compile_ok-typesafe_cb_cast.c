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

static void take_any(struct any *any)
{
	(void)any;
}

int main(void)
{
	/* Otherwise we get unused warnings for these. */
	struct foo *foo = NULL;
	struct bar *bar = NULL;
	struct baz *baz = NULL;

	take_any(typesafe_cb_cast3(struct any *,
				   struct foo *, struct bar *, struct baz *,
				   foo));
	take_any(typesafe_cb_cast3(struct any *, 
				   struct foo *, struct bar *, struct baz *,
				   bar));
	take_any(typesafe_cb_cast3(struct any *, 
				   struct foo *, struct bar *, struct baz *,
				   baz));
	return 0;
}
