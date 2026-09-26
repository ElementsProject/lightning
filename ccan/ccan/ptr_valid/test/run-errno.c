/* Regression test: ptr_valid.h documents "Sets errno to EFAULT on
 * failure", but the /proc/self/maps path and the alignment check
 * return false without setting errno.  Currently fails all 3 tests. */
#include <unistd.h>
#include <ccan/ptr_valid/ptr_valid.h>
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#include <ccan/tap/tap.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>

int main(void)
{
	char *page;

	plan_tests(3);
	alarm(10);

	page = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (page == MAP_FAILED)
		plan_skip_all("mmap failed");
	munmap(page, getpagesize());

	/* Unmapped pointer (maps path). */
	errno = 0;
	ok1(!ptr_valid_read(page) && errno == EFAULT);

	/* Misaligned pointer. */
	errno = 0;
	ok1(!ptr_valid(page + 1, getpagesize(), 1, false) && errno == EFAULT);

	/* Read-only page, write check (maps path). */
	page = mmap(NULL, getpagesize(), PROT_READ,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (page == MAP_FAILED)
		plan_skip_all("mmap failed");
	errno = 0;
	ok1(!ptr_valid_write(page) && errno == EFAULT);
	munmap(page, getpagesize());

	return exit_status();
}
