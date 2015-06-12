/* We can't use the normal "#include the .c file" trick, since this is
   contaminated by str.h's macro overrides.  So we put it in all tests
   like this. */
#define CCAN_STR_DEBUG 1
#include <ccan/str/debug.c>
