#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <err.h>

int main(void)
{
	plan_tests(6);

	ok1(sizeof(be64) == 8);
	ok1(sizeof(be32) == 4);
	ok1(sizeof(be16) == 2);

	ok1(sizeof(le64) == 8);
	ok1(sizeof(le32) == 4);
	ok1(sizeof(le16) == 2);

	return exit_status();
}
