#include <ccan/build_assert/build_assert.h>

int main(void)
{
#ifdef FAIL
	return BUILD_ASSERT_OR_ZERO(1 == 0);
#else
	return 0;
#endif
}
