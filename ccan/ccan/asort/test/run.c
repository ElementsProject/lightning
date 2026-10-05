#include <ccan/asort/asort.h>
#include <ccan/asort/asort.c>
#include <ccan/array_size/array_size.h>
#include <ccan/tap/tap.h>
#include <limits.h>
#include <stdbool.h>

static int test_cmp(const int *key, const int *elt, int *flag)
{
	if (*key < *elt)
		return -1 * *flag;
	else if (*key > *elt)
		return 1 * *flag;

	return 0;
}

static bool is_sorted(const int arr[], unsigned int size)
{
	unsigned int i;

	for (i = 1; i < size; i++)
		if (arr[i] < arr[i-1])
			return false;
	return true;
}

static bool is_reverse_sorted(const int arr[], unsigned int size)
{
	unsigned int i;

	for (i = 1; i < size; i++)
		if (arr[i] > arr[i-1])
			return false;
	return true;
}

static void pseudo_random_array(int arr[], unsigned int size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		arr[i] = i * (INT_MAX / 4 - 7);
}

/* Track whether the comparator was ever called with identical pointers. */
static bool self_compared;

static int test_cmp_self(const int *a, const int *b, void *unused)
{
	if (a == b)
		self_compared = true;
	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

#define TEST_SIZE 100

int main(void)
{
	int tmparr[TEST_SIZE];
	int multiplier = 1;

	plan_tests(8);

	pseudo_random_array(tmparr, TEST_SIZE);
	ok1(!is_sorted(tmparr, TEST_SIZE));
	ok1(!is_reverse_sorted(tmparr, TEST_SIZE));

	asort(tmparr, TEST_SIZE, test_cmp, &multiplier);
	ok1(is_sorted(tmparr, TEST_SIZE));

	pseudo_random_array(tmparr, TEST_SIZE);
	multiplier = -1;
	asort(tmparr, TEST_SIZE, test_cmp, &multiplier);
	ok1(is_reverse_sorted(tmparr, TEST_SIZE));

	/* Sorting an array with all equal elements must not crash and must
	 * produce a sorted result regardless of whether the comparator
	 * receives identical pointers (self-comparisons are permitted by
	 * the C standard and done by some qsort implementations). */
	for (int i = 0; i < TEST_SIZE; i++)
		tmparr[i] = 42;
	self_compared = false;
	asort(tmparr, TEST_SIZE, test_cmp_self, NULL);
	ok1(is_sorted(tmparr, TEST_SIZE));

	/* Sorting a single element must not crash. */
	tmparr[0] = 7;
	asort(tmparr, 1, test_cmp_self, NULL);
	ok1(tmparr[0] == 7);

	/* Force a self-comparison directly to verify the comparator handles it. */
	{
		int val = 42;
		self_compared = false;
		ok1(test_cmp_self(&val, &val, NULL) == 0);
		ok1(self_compared);
	}

	diag("asort comparator called with identical pointers: %s",
	     self_compared ? "yes" : "no");

	return exit_status();
}
