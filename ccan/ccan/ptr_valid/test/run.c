#include <ccan/ptr_valid/ptr_valid.h>
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#include <ccan/tap/tap.h>
#include <sys/mman.h>

static bool check_batch(char *p, unsigned int num, bool expect)
{
	struct ptr_valid_batch batch;
	unsigned int i;

	if (!ptr_valid_batch_start(&batch))
		return false;
	for (i = 0; i < num; i++) {
		if (ptr_valid_batch(&batch, p + i, 1, 1, false) != expect)
			return false;
		if (ptr_valid_batch(&batch, p + i, 1, 1, true) != expect)
			return false;
	}
	ptr_valid_batch_end(&batch);
	return true;
}

int main(void)
{
	char *page;

	/* This is how many tests you plan to run */
	plan_tests(30);

	page = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	ok1(ptr_valid_read(page));
	ok1(ptr_valid_write(page));
	ok1(ptr_valid(page, 1, getpagesize(), false));
	ok1(ptr_valid(page, 1, getpagesize(), true));

	/* Test alignment constraints. */
	ok1(ptr_valid(page, getpagesize(), getpagesize(), false));
	ok1(ptr_valid(page, getpagesize(), getpagesize(), true));
	ok1(!ptr_valid(page+1, getpagesize(), 1, false));
	ok1(!ptr_valid(page+1, getpagesize(), 1, true));

	/* Test batch. */
	ok1(check_batch(page, getpagesize(), true));

	/* Unmap, all should fail. */
	munmap(page, getpagesize());
	ok1(!ptr_valid_read(page));
	ok1(!ptr_valid_write(page));
	ok1(!ptr_valid(page, 1, getpagesize(), false));
	ok1(!ptr_valid(page, 1, getpagesize(), true));

	/* Test alignment constraints. */
	ok1(!ptr_valid(page, getpagesize(), getpagesize(), false));
	ok1(!ptr_valid(page, getpagesize(), getpagesize(), true));
	ok1(!ptr_valid(page+1, getpagesize(), 1, false));
	ok1(!ptr_valid(page, getpagesize(), 1, true));

	/* Test batch (slow, since each fails, so reduce count). */
	ok1(check_batch(page, 4, false));

	/* Check read-only */
	page = mmap(NULL, getpagesize(), PROT_READ,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	ok1(ptr_valid_read(page));
	ok1(!ptr_valid_write(page));
	ok1(ptr_valid(page, 1, getpagesize(), false));
	ok1(!ptr_valid(page, 1, getpagesize(), true));

	/* Test alignment constraints. */
	ok1(ptr_valid(page, getpagesize(), getpagesize(), false));
	ok1(!ptr_valid(page, getpagesize(), getpagesize(), true));
	ok1(!ptr_valid(page+1, getpagesize(), 1, false));
	ok1(!ptr_valid(page+1, getpagesize(), 1, true));
	munmap(page, getpagesize());

	/* Check for overrun. */
	page = mmap(NULL, getpagesize()*2, PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	munmap(page + getpagesize(), getpagesize());

	ok1(ptr_valid(page, 1, getpagesize(), false));
	ok1(ptr_valid(page, 1, getpagesize(), true));
	ok1(!ptr_valid(page, 1, getpagesize()+1, false));
	ok1(!ptr_valid(page, 1, getpagesize()+1, true));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
