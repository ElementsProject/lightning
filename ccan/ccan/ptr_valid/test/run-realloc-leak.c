/* Regression test: grab() and add_map() overwrite their pointer with
 * realloc()'s return value, so a failed realloc leaks the old buffer.
 * We interpose malloc/realloc/free by macro (this file includes
 * ptr_valid.c directly) and inject a failure at each growth call.
 * Currently fails: not ok 1 and not ok 2. */
#include <unistd.h>
#include <ccan/ptr_valid/ptr_valid.h>
#include <stdint.h>

static void *live[64];
static unsigned int nlive;
static size_t fail_realloc_size;

static void track(void *p)
{
	if (p && nlive < sizeof(live)/sizeof(live[0]))
		live[nlive++] = p;
}

static void untrack(void *p)
{
	unsigned int i;

	for (i = 0; i < nlive; i++) {
		if (live[i] == p) {
			live[i] = live[--nlive];
			return;
		}
	}
}

static void *my_malloc(size_t size)
{
	void *p;
#undef malloc
	p = malloc(size);
#define malloc my_malloc
	track(p);
	return p;
}

static void *my_realloc(void *old, size_t size)
{
	void *p;
	uintptr_t o = (uintptr_t)old;

	if (fail_realloc_size && size == fail_realloc_size)
		return NULL;
#undef realloc
	p = realloc(old, size);
#define realloc my_realloc
	if (p) {
		untrack((void *)o);
		track(p);
	}
	return p;
}

static void my_free(void *p)
{
	if (p)
		untrack(p);
#undef free
	free(p);
#define free my_free
}

#define malloc my_malloc
#define realloc my_realloc
#define free my_free
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#undef malloc
#undef realloc
#undef free

#include <ccan/tap/tap.h>
#include <sys/mman.h>
#include <signal.h>

int main(void)
{
	char *region;
	int i;
	struct ptr_valid_batch batch;

	alarm(20);

	/* Silence "defined but not used" when ptr_valid.c's
	 * HAVE_PROC_SELF_MAPS-less build calls no malloc at all. */
	(void)my_malloc;
	(void)my_realloc;
	(void)my_free;

	/* Split a 1000-page mapping into alternating RO/RW VMAs so
	 * /proc/self/maps exceeds grab()'s initial 16k buffer and has
	 * more entries than add_map()'s initial 16 slots.
	 *
	 * Must resolve this (and plan accordingly) before the single
	 * plan_tests()/plan_skip_all() call tap allows. */
	region = mmap(NULL, 1000 * 4096, PROT_READ|PROT_WRITE,
		      MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (region == MAP_FAILED) {
		plan_skip_all("mmap failed");
		return exit_status();
	}
	for (i = 0; i < 1000; i += 2)
		if (mprotect(region + i * 4096, 4096, PROT_READ) != 0) {
			plan_skip_all("mprotect failed");
			return exit_status();
		}

	plan_tests(2);

	/* grab(): fail the 16384 -> 32768 buffer growth. */
	fail_realloc_size = 32768 + 1;
	nlive = 0;
	ptr_valid_batch_start(&batch);
	ptr_valid_batch_end(&batch);
	ok1(nlive == 0);

	/* add_map(): fail the 16 -> 32 entry array growth. */
	fail_realloc_size = sizeof(struct ptr_valid_map) * 32;
	nlive = 0;
	ptr_valid_batch_start(&batch);
	ptr_valid_batch_end(&batch);
	ok1(nlive == 0);

	munmap(region, 1000 * 4096);
	return exit_status();
}
