/* CC0 (Public domain) - see LICENSE file for details */
#include "config.h"
#include <ccan/str/str_debug.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>

#ifdef CCAN_STR_DEBUG
/* Because we mug the real ones with macros, we need our own wrappers. */
int str_isalnum(int i)
{
	assert(i >= -1 && i < 256);
	return isalnum(i);
}

int str_isalpha(int i)
{
	assert(i >= -1 && i < 256);
	return isalpha(i);
}

int str_isascii(int i)
{
	assert(i >= -1 && i < 256);
	return isascii(i);
}

#if HAVE_ISBLANK
int str_isblank(int i)
{
	assert(i >= -1 && i < 256);
	return isblank(i);
}
#endif

int str_iscntrl(int i)
{
	assert(i >= -1 && i < 256);
	return iscntrl(i);
}

int str_isdigit(int i)
{
	assert(i >= -1 && i < 256);
	return isdigit(i);
}

int str_isgraph(int i)
{
	assert(i >= -1 && i < 256);
	return isgraph(i);
}

int str_islower(int i)
{
	assert(i >= -1 && i < 256);
	return islower(i);
}

int str_isprint(int i)
{
	assert(i >= -1 && i < 256);
	return isprint(i);
}

int str_ispunct(int i)
{
	assert(i >= -1 && i < 256);
	return ispunct(i);
}

int str_isspace(int i)
{
	assert(i >= -1 && i < 256);
	return isspace(i);
}

int str_isupper(int i)
{
	assert(i >= -1 && i < 256);
	return isupper(i);
}

int str_isxdigit(int i)
{
	assert(i >= -1 && i < 256);
	return isxdigit(i);
}

#undef strstr
#undef strchr
#undef strrchr

char *str_strstr(const char *haystack, const char *needle)
{
	return strstr(haystack, needle);
}

char *str_strchr(const char *haystack, int c)
{
	return strchr(haystack, c);
}

char *str_strrchr(const char *haystack, int c)
{
	return strrchr(haystack, c);
}
#endif
