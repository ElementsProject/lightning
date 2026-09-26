/* CC0 (Public domain) - see LICENSE file for details */
#include <ccan/str/str.h>

size_t strcount(const char *haystack, const char *needle)
{
	size_t i = 0, nlen = strlen(needle);

	if (nlen == 0)
		return 0;

	while ((haystack = strstr(haystack, needle)) != NULL) {
		i++;
		haystack += nlen;
	}
	return i;
}
