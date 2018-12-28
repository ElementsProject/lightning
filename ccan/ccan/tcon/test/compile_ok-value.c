#include <ccan/tcon/tcon.h>
#include <ccan/build_assert/build_assert.h>
#include <stdlib.h>
#include <stddef.h>

struct container {
	void *p;
};

struct val_container {
	struct container raw;
	TCON(TCON_VALUE(fixed_val, 17));
};

struct other_struct {
	char junk1;
	int x1;
	long junk2;
	char *x2;
	short junk3;
};

struct offs_container {
	struct container raw;
	TCON(TCON_VALUE(off1, offsetof(struct other_struct, x1));
	     TCON_VALUE(off2, offsetof(struct other_struct, x2)));
};

int main(void)
{
	struct val_container valcon;
	struct offs_container offscon;
	TCON_WRAP(struct container, TCON_VALUE(fixed_val, 17)) valconw;
	TCON_WRAP(struct container,
		  TCON_VALUE(off1, offsetof(struct other_struct, x1));
		  TCON_VALUE(off2, offsetof(struct other_struct, x2))) offsconw;

	BUILD_ASSERT(tcon_value(&valcon, fixed_val) == 17);
	BUILD_ASSERT(tcon_value(&valconw, fixed_val) == 17);

	BUILD_ASSERT(tcon_value(&offscon, off1)
		     == offsetof(struct other_struct, x1));
	BUILD_ASSERT(tcon_value(&offscon, off2)
		     == offsetof(struct other_struct, x2));
	BUILD_ASSERT(tcon_value(&offsconw, off1)
		     == offsetof(struct other_struct, x1));
	BUILD_ASSERT(tcon_value(&offsconw, off2)
		     == offsetof(struct other_struct, x2));

	return 0;
}
