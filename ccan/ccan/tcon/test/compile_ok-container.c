#include <stdlib.h>

#include <ccan/tcon/tcon.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/tap/tap.h>

struct inner {
	int inner_val;
};

struct outer {
	int outer_val;
	struct inner inner;
};

struct info_base {
	char *infop;
};

struct info_tcon {
	struct info_base base;
	TCON(TCON_CONTAINER(fi, struct outer, inner));
};

int main(void)
{
	/* Const should work! */
	const struct outer *ovar = NULL;
	struct outer *o;
	struct info_tcon info;

	o = tcon_container_of(&info, fi, &ovar->inner);
	return (o == ovar);
}

