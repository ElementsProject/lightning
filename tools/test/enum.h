#ifndef LIGHTNING_TOOLS_TEST_ENUM_H
#define LIGHTNING_TOOLS_TEST_ENUM_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

#define TEST_IFDEF 0

enum test_enum {
	TEST_ONE,
	TEST_TWO,
};

void towire_test_enum(u8 **pptr, const enum test_enum test_enum);
enum test_enum fromwire_test_enum(const u8 **cursor, size_t *max);
void printwire_test_enum(const char *fieldname, const enum test_enum *test_enum);

#endif /* LIGHTNING_TOOLS_TEST_ENUM_H */
