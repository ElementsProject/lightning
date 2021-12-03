#include "config.h"
#include "enum.h"
#include <stdio.h>

void towire_test_enum(u8 **pptr, const enum test_enum test_enum)
{
	printf("this would have been the towire for enum %u\n", test_enum);
}

enum test_enum fromwire_test_enum(const u8 **cursor, size_t *max)
{
	printf("fromwire_test_enum at %zu\n", *max);
	return TEST_ONE;
}

void printwire_test_enum(const char *fieldname, const enum test_enum *test_enum)
{
	printf("%u\n", *test_enum);
}
