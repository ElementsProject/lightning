#include <ccan/array_size/array_size.h>

int main(void)
{
	void *vp = (void *)0;
#ifdef FAIL
	/* A void * is a pointer, not an array: the typeof/types_compatible_p
	 * guard must reject this (unlike comparison-based checks, which a
	 * void type silently bypasses -- see the check_type/container_of
	 * audits). */
	return ARRAY_SIZE(vp);
#if !HAVE_TYPEOF || !HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if _array_size_chk is a noop."
#endif
#else
	(void)vp;
	return 0;
#endif
}
