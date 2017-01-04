#include <ccan/autodata/autodata.h>
/* Include the C files directly. */
#include <ccan/autodata/autodata.c>
#include <ccan/tap/tap.h>

AUTODATA_TYPE(autostrings, char);

AUTODATA(autostrings, "genuine");

#if !HAVE_SECTION_START_STOP
/* These are all fake, to test the various failure paths. */
/* Hopefully fake_alpha or fake_omega will test run-past-end. */
static const void *NEEDED fake_alpha[] = { (void *)AUTODATA_MAGIC };

/* Wrong magic in the middle. */
static const void *NEEDED fake1[] = { (void *)(AUTODATA_MAGIC ^ 0x10000),
				      (void *)&fake1,
				      "fake1",
				      (void *)"autostrings" };

/* Wrong self pointer. */
static const void *NEEDED fake2[] = { (void *)AUTODATA_MAGIC,
				      (void *)&fake1,
				      "fake2",
				      (void *)"autostrings" };

/* Wrong name. */
static const void *NEEDED fake3[] = { (void *)AUTODATA_MAGIC,
				      (void *)&fake3,
				      "fake3",
				      (void *)"autostrings2" };

/* Invalid self-pointer. */
static const void *NEEDED fake4[] = { (void *)AUTODATA_MAGIC,
				      (void *)1UL,
				      "fake4",
				      (void *)"autostrings" };

/* Invalid name pointer */
static const void *NEEDED fake5[] = { (void *)AUTODATA_MAGIC,
				      (void *)&fake5,
				      "fake5",
				      (void *)1UL };

/* Invalid contents pointer */
static const void *NEEDED fake6[] = { (void *)AUTODATA_MAGIC,
				      (void *)&fake6,
				      (char *)1UL,
				      (void *)"autostrings" };

static const void *NEEDED fake_omega[] = { (void *)AUTODATA_MAGIC };
#endif

int main(void)
{
	char **table;
	size_t num;

	/* This is how many tests you plan to run */
	plan_tests(2);

	table = autodata_get(autostrings, &num);
	ok1(num == 2);
	ok1((!strcmp(table[0], "genuine") && !strcmp(table[1], "helper"))
	    || (!strcmp(table[1], "genuine") && !strcmp(table[0], "helper")));

	autodata_free(table);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
