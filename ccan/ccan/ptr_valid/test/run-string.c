#include <ccan/ptr_valid/ptr_valid.h>
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#include <ccan/tap/tap.h>
#include <sys/mman.h>

int main(void)
{
	char *page;
	struct ptr_valid_batch *batch = malloc(sizeof *batch);

	/* This is how many tests you plan to run */
	plan_tests(14);

	page = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	strcpy(page, "hello");
	ok1(ptr_valid_read(page));
	ok1(ptr_valid_write(page));
	ok1(ptr_valid_string(page));

	ok1(ptr_valid_batch_start(batch));
	ok1(ptr_valid_batch_string(batch, page));
	ptr_valid_batch_end(batch);

	/* Check invalid case. */
	munmap(page, getpagesize());
	ok1(!ptr_valid_string(page));

	ok1(ptr_valid_batch_start(batch));
	ok1(!ptr_valid_batch_string(batch, page));
	ptr_valid_batch_end(batch);

	/* Check for overrun. */
	page = mmap(NULL, getpagesize()*2, PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	munmap(page + getpagesize(), getpagesize());

	memset(page, 'a', getpagesize());
	ok1(!ptr_valid_string(page));
	ok1(ptr_valid_batch_start(batch));
	ok1(!ptr_valid_batch_string(batch, page));
	ptr_valid_batch_end(batch);

	page[getpagesize()-1] = '\0';
	ok1(ptr_valid_string(page));

	ok1(ptr_valid_batch_start(batch));
	ok1(ptr_valid_batch_string(batch, page));
	ptr_valid_batch_end(batch);
	munmap(page, getpagesize());

	free(batch);
	/* This exits depending on whether all tests passed */
	return exit_status();
}
