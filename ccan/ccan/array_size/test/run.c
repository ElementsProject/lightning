#include <ccan/array_size/array_size.h>
#include <ccan/tap/tap.h>

static char array1[1];
static int array2[2];
static unsigned long array3[3][5];
struct foo {
	unsigned int a, b;
	char string[100];
};
static struct foo array4[4];

/* Make sure they can be used in initializers. */
static int array1_size = ARRAY_SIZE(array1);
static int array2_size = ARRAY_SIZE(array2);
static int array3_size = ARRAY_SIZE(array3);
static int array4_size = ARRAY_SIZE(array4);

int main(int argc, char *argv[])
{
	plan_tests(8);
	ok1(array1_size == 1);
	ok1(array2_size == 2);
	ok1(array3_size == 3);
	ok1(array4_size == 4);

	ok1(ARRAY_SIZE(array1) == 1);
	ok1(ARRAY_SIZE(array2) == 2);
	ok1(ARRAY_SIZE(array3) == 3);
	ok1(ARRAY_SIZE(array4) == 4);

	return exit_status();
}
