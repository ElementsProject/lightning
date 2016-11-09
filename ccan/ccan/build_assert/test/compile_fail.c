#include <ccan/build_assert/build_assert.h>

int main(void)
{
#ifdef FAIL
	BUILD_ASSERT(1 == 0);
#endif
	return 0;
}
