/* Regression test: run_child() exits via exit() instead of _exit(),
 * so in the no-/proc/self/maps fallback (containers/chroots without
 * /proc) the child flushes stdio buffers it inherited from the parent
 * a second time.  We force the fallback by undefining
 * HAVE_PROC_SELF_MAPS (same code path as /proc being unavailable).
 * Currently fails: not ok 2. */
#include <unistd.h>
#include <ccan/ptr_valid/ptr_valid.h>
#undef HAVE_PROC_SELF_MAPS
#define HAVE_PROC_SELF_MAPS 0
/* Include the C files directly. */
#include <ccan/ptr_valid/ptr_valid.c>
#include <ccan/tap/tap.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>

#if defined(__has_include)
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define HAVE_VALGRIND_H 1
#endif
#endif

int main(void)
{
	char tmpl[] = "/tmp/ptr_valid-flush-XXXXXX";
	char *page;
	int fd;
	FILE *f;
	long len;

#ifdef HAVE_VALGRIND_H
	/* valgrind's own child-exit path flushes the inherited buffer,
	 * masking the module's behavior. */
	if (RUNNING_ON_VALGRIND) {
		plan_skip_all("valgrind perturbs stdio across fork");
		return exit_status();
	}
#endif

	plan_tests(2);
	alarm(10);

	fd = mkstemp(tmpl);
	if (fd < 0)
		plan_skip_all("mkstemp failed");
	f = fdopen(fd, "w");
	if (!f)
		plan_skip_all("fdopen failed");
	unlink(tmpl);

	/* Fully buffered stream with pending data at fork time. */
	setvbuf(f, NULL, _IOFBF, 4096);
	fwrite("unflushed-data", 1, 14, f);

	page = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (page == MAP_FAILED)
		plan_skip_all("mmap failed");

	/* Creates the probing child; ptr_valid_batch_end() closes the
	 * pipe, the child sees EOF and calls exit(0), flushing its
	 * inherited copy of f's buffer. */
	ok1(ptr_valid_read(page));

	/* The parent now flushes its own copy. */
	fflush(f);
	len = ftell(f);
	fclose(f);
	munmap(page, getpagesize());

	ok1(len == 14);
	return exit_status();
}
