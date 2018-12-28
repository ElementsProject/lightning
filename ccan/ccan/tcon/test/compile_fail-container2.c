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
	TCON(TCON_CONTAINER(concan, struct outer, inner));
};

int main(void)
{
	struct info_tcon info;
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
