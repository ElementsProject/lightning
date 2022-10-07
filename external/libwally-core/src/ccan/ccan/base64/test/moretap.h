#ifndef _BASE64_MORETAP_H
#define _BASE64_MORETAP_H

#include <ccan/str/str.h>

/**
 * is_str - OK if strings are equal
 * @e1: expression for the variable string
 * @e2: expression for the expected string
 *
 * If the strings are equal, the test passes.
 *
 * Example:
 *     is_str(give_me_a_fred(),"fred");
 */
static void _is_str(char *got,const char *expected, const char *got_string, const char *expected_string, const char *func, const char *file, int line) {
	if (streq(expected,got)) {
		_gen_result(1, func, file, line,"%s eq %s",
			    got_string,expected_string);
	} else {
		_gen_result(0, func, file, line,"%s eq %s",
			    got_string,expected_string);
		diag("Expected: %s",expected);
		diag("     Got: %s",got);
	}
}
# define is_str(got,expected) _is_str(got,expected,#got,#expected,__func__, __FILE__, __LINE__)


/**
 * is_int - OK if arguments are equal when cast to integers
 * @e1: expression for the number
 * @e2: expression for the expected number
 *
 * If the numbers are equal, the test passes.
 *
 * Example:
 *     is_int(give_me_17(),17);
 */
# define is_int(e1,e2 ...)						\
  (((int)e1)==((int)e2) ?						\
   _gen_result(1, __func__, __FILE__, __LINE__,"%s == %s",#e1,#e2) :	\
   (_gen_result(0, __func__, __FILE__, __LINE__,"%s == %s",#e1,#e2)) || (diag("Expected: %d",e2),diag("     Got: %d",e1),0)) /* diag is void; note commas. */



/**
 * is_mem - OK if arguments are identical up to length @e3
 * @e1: expression for the buffer
 * @e2: expression for the expected buffer
 * @e2: length to compare in buffers
 *
 * If the buffers are equal up to @e2, the test passes.
 *
 * Example:
 *     is_mem(give_me_foo(),"foo",3);
 */
static void _is_mem(const char *got, const char *expected, const size_t len,
	      const char *got_string, const char *expected_string, const char *len_string,
	      const char *func, const char *file, int line) {
	size_t offset = 0;

	for (offset=0; offset<len; offset++) {
		if (got[offset] != expected[offset]) {
			_gen_result(0, func, file, line,"%s eq %s",got_string,expected_string);
			/* diag("Expected: %s",e2); */
			/* diag("     Got: %s",e1); */
			diag("Buffers differ at offset %zd (got=0x%02x expected=0x%02x)",
			     offset,got[offset],expected[offset]);
			return;
		}
	}

	_gen_result(1, __func__, __FILE__, __LINE__,"%s eq %s",
		    expected_string,got_string);
}
# define is_mem(got,expected,len) \
	_is_mem(got,expected,len,#got,#expected,#len,__func__, __FILE__, __LINE__)

/**
 * is_size_t - OK if arguments are equal when cast to size_t
 * @e1: expression for the number
 * @e2: expression for the expected number
 *
 * If the numbers are equal, the test passes.
 *
 * Example:
 *     is_size_t(give_me_17(),17);
 */
# define is_size_t(e1,e2 ...)						\
  ((size_t)(e1)==((size_t)e2) ?						\
   _gen_result(1, __func__, __FILE__, __LINE__,"%s == %s",#e1,#e2) :	\
   (_gen_result(0, __func__, __FILE__, __LINE__,			\
		"%s == %s",#e1,#e2)) || (diag("Expected: %zd",(size_t)e2),diag("     Got: %zd",(size_t)e1),0)) /* diag is void; note commas. */

#endif
