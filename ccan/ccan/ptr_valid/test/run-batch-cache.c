/* Regression test: ptr_valid_batch()'s single-page cache ignores the
 * read/write flag.  On a read-only page, a cached read result makes
 * ptr_valid_batch_write() claim the page is writable (and a cached
 * write failure makes ptr_valid_batch_read() claim it is unreadable).
 * Currently fails: not ok 2 and not ok 4. */
#include <ccan/ptr_valid/ptr_valid.h>
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#include <ccan/tap/tap.h>
#include <sys/mman.h>
#include <signal.h>

int main(void)
{
	char *page;
	struct ptr_valid_batch batch;

	plan_tests(4);
	alarm(10);

	page = mmap(NULL, getpagesize(), PROT_READ,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (page == MAP_FAILED)
		plan_skip_all("mmap failed");

	/* A cached read hit must not validate a write on the same page. */
	ptr_valid_batch_start(&batch);
	ok1(ptr_valid_batch_read(&batch, page));
	ok1(!ptr_valid_batch_write(&batch, page));
	ptr_valid_batch_end(&batch);

	/* A cached write miss must not invalidate a read either. */
	ptr_valid_batch_start(&batch);
	ok1(!ptr_valid_batch_write(&batch, page));
	ok1(ptr_valid_batch_read(&batch, page));
	ptr_valid_batch_end(&batch);

	munmap(page, getpagesize());
	return exit_status();
}
