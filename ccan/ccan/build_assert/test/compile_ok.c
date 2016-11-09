#include <ccan/build_assert/build_assert.h>

int main(void)
{
	BUILD_ASSERT(1 == 1);
	return 0;
}
