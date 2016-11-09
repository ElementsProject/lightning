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

int main(void)
{
	TCON_WRAP(struct info_base,
		  TCON_CONTAINER(concan, struct outer, inner)) info;
	struct outer ovar;
#ifdef FAIL
#if !HAVE_TYPEOF
#error We cannot detect type problems without HAVE_TYPEOF
#endif
	char *outerp = NULL;
#else
	struct outer *outerp = &ovar;
#endif

	return tcon_member_of(&info, concan, outerp) == &ovar.inner;
}
