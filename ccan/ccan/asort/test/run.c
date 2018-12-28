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

#define TEST_SIZE 100

int main(void)
{
	int tmparr[TEST_SIZE];
	int multiplier = 1;

	plan_tests(4);

	pseudo_random_array(tmparr, TEST_SIZE);
	ok1(!is_sorted(tmparr, TEST_SIZE));
	ok1(!is_reverse_sorted(tmparr, TEST_SIZE));

	asort(tmparr, TEST_SIZE, test_cmp, &multiplier);
	ok1(is_sorted(tmparr, TEST_SIZE));

	pseudo_random_array(tmparr, TEST_SIZE);
	multiplier = -1;
	asort(tmparr, TEST_SIZE, test_cmp, &multiplier);
	ok1(is_reverse_sorted(tmparr, TEST_SIZE));

	return exit_status();
}
