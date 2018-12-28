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

struct outer0 {
	struct inner inner;
	int outer0_val;
};

struct info_base {
	char *infop;
};

struct info_tcon {
	struct info_base base;
	TCON(TCON_CONTAINER(fi, struct outer, inner);
	     TCON_CONTAINER(fi2, struct outer0, inner));
};

int main(void)
{
	struct info_tcon info;
	TCON_WRAP(struct info_base,
		  TCON_CONTAINER(fi, struct outer, inner);
		  TCON_CONTAINER(fi2, struct outer0, inner)) infow;
	struct outer ovar;
	struct outer0 ovar2;

	plan_tests(12);

	ok1(tcon_container_of(&info, fi, &ovar.inner) == &ovar);
	ok1(tcon_member_of(&info, fi, &ovar) == &ovar.inner);
	ok1(tcon_container_of(&infow, fi, &ovar.inner) == &ovar);
	ok1(tcon_member_of(&infow, fi, &ovar) == &ovar.inner);

	ok1(tcon_container_of(&info, fi2, &ovar2.inner) == &ovar2);
	ok1(tcon_member_of(&info, fi2, &ovar2) == &ovar2.inner);
	ok1(tcon_container_of(&infow, fi2, &ovar2.inner) == &ovar2);
	ok1(tcon_member_of(&infow, fi2, &ovar2) == &ovar2.inner);

	/* Check handling of NULLs */
	ok1(tcon_container_of(&info, fi, NULL) == NULL);
	ok1(tcon_member_of(&info, fi, NULL) == NULL);
	ok1(tcon_container_of(&infow, fi, NULL) == NULL);
	ok1(tcon_member_of(&infow, fi, NULL) == NULL);

	return 0;
}
