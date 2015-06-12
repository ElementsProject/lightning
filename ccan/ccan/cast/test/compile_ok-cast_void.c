#include <ccan/cast/cast.h>

static void *remove_void(const void *p)
{
	return cast_const(void *, p);
}

int main(void)
{
	void *p = remove_void("foo");
	return !p;
}
