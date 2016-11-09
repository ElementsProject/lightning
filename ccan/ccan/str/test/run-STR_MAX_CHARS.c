#include <ccan/str/str.h>
#include <stdlib.h>
#include <stdio.h>
#include <ccan/tap/tap.h>
#include <stdint.h>

int main(void)
{
	char str[1000];
	struct {
		uint8_t u1byte;
		int8_t s1byte;
		uint16_t u2byte;
		int16_t s2byte;
		uint32_t u4byte;
		int32_t s4byte;
		uint64_t u8byte;
		int64_t s8byte;
		void *ptr;
	} types;

	plan_tests(13);

	memset(&types, 0xFF, sizeof(types));

	/* Hex versions */
	sprintf(str, "0x%llx", (unsigned long long)types.u1byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u1byte));
	sprintf(str, "0x%llx", (unsigned long long)types.u2byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u2byte));
	sprintf(str, "0x%llx", (unsigned long long)types.u4byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u4byte));
	sprintf(str, "0x%llx", (unsigned long long)types.u8byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u8byte));

	/* Decimal versions */
	sprintf(str, "%u", types.u1byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u1byte));
	sprintf(str, "%d", types.s1byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.s1byte));
	sprintf(str, "%u", types.u2byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u2byte));
	sprintf(str, "%d", types.s2byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.s2byte));
	sprintf(str, "%u", types.u4byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u4byte));
	sprintf(str, "%d", types.s4byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.s4byte));
	sprintf(str, "%llu", (unsigned long long)types.u8byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.u8byte));
	sprintf(str, "%lld", (long long)types.s8byte);
	ok1(strlen(str) < STR_MAX_CHARS(types.s8byte));

	/* Pointer version. */
	sprintf(str, "%p", types.ptr);
	ok1(strlen(str) < STR_MAX_CHARS(types.ptr));

	return exit_status();
}				
