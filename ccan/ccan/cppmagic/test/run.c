#include "config.h"

#include <string.h>

#include <ccan/cppmagic/cppmagic.h>
#include <ccan/tap/tap.h>

static inline void check1(const char *orig, const char *expand,
			  const char *match)
{
	ok(strcmp(expand, match) == 0,
	   "%s => %s : %s", orig, expand, match);
}

#define CHECK1(orig, match) \
	check1(#orig, CPPMAGIC_STRINGIFY(orig), match)

#define TESTRECURSE()	R CPPMAGIC_DEFER1(_TESTRECURSE) ()()
#define _TESTRECURSE()	TESTRECURSE

#define TESTMAP1(x)	<<x>>

#define TESTMAP2(x)		[[ x
#define TESTMAP3(x)		x ]]

#define TEST2MAP(x, y)	x ** y

int main(void)
{
	plan_tests(42);

	CHECK1(CPPMAGIC_NOTHING(), "");
	CHECK1(CPPMAGIC_GLUE2(a, b), "ab");

	CHECK1(CPPMAGIC_1ST(a), "a");
	CHECK1(CPPMAGIC_1ST(a, b), "a");
	CHECK1(CPPMAGIC_1ST(a, b, c), "a");

	CHECK1(CPPMAGIC_2ND(a, b), "b");
	CHECK1(CPPMAGIC_2ND(a, b, c), "b");

	CHECK1(CPPMAGIC_ISZERO(0), "1");
	CHECK1(CPPMAGIC_ISZERO(1), "0");
	CHECK1(CPPMAGIC_ISZERO(123), "0");
	CHECK1(CPPMAGIC_ISZERO(abc), "0");

	CHECK1(CPPMAGIC_NONZERO(0), "0");
	CHECK1(CPPMAGIC_NONZERO(1), "1");
	CHECK1(CPPMAGIC_NONZERO(123), "1");
	CHECK1(CPPMAGIC_NONZERO(abc), "1");

	CHECK1(CPPMAGIC_NONEMPTY(), "0");
	CHECK1(CPPMAGIC_NONEMPTY(0), "1");
	CHECK1(CPPMAGIC_NONEMPTY(a, b, c), "1");

	CHECK1(CPPMAGIC_ISEMPTY(), "1");
	CHECK1(CPPMAGIC_ISEMPTY(0), "0");
	CHECK1(CPPMAGIC_ISEMPTY(a, b, c), "0");
	
	CHECK1(CPPMAGIC_IFELSE(0)(abc)(def), "def");
	CHECK1(CPPMAGIC_IFELSE(1)(abc)(def), "abc");
	CHECK1(CPPMAGIC_IFELSE(not zero)(abc)(def), "abc");

	CHECK1(TESTRECURSE(), "R R _TESTRECURSE ()()");
	CHECK1(CPPMAGIC_EVAL1(TESTRECURSE()), "R R R _TESTRECURSE ()()");
	CHECK1(CPPMAGIC_EVAL2(TESTRECURSE()), "R R R R R _TESTRECURSE ()()");

	CHECK1(CPPMAGIC_MAP(TESTMAP1), "");
	CHECK1(CPPMAGIC_MAP(TESTMAP1, a), "<<a>>");
	CHECK1(CPPMAGIC_MAP(TESTMAP1, a, b), "<<a>> , <<b>>");
	CHECK1(CPPMAGIC_MAP(TESTMAP1, a, b, c), "<<a>> , <<b>> , <<c>>");

	CHECK1(CPPMAGIC_2MAP(TEST2MAP), "");
	CHECK1(CPPMAGIC_2MAP(TEST2MAP, a, 1), "a ** 1");
	CHECK1(CPPMAGIC_2MAP(TEST2MAP, a, 1, b, 2), "a ** 1 , b ** 2");
	
	CHECK1(CPPMAGIC_JOIN(;), "");
	CHECK1(CPPMAGIC_JOIN(;, a), "a");
	CHECK1(CPPMAGIC_JOIN(;, a, b), "a ; b");
	CHECK1(CPPMAGIC_JOIN(;, a, b, c), "a ; b ; c");

	/* Check chaining of MAPs */
	CHECK1(CPPMAGIC_MAP(TESTMAP2, CPPMAGIC_MAP(TESTMAP3)), "");
	CHECK1(CPPMAGIC_MAP(TESTMAP2, CPPMAGIC_MAP(TESTMAP3, a)), "[[ a ]]");
	CHECK1(CPPMAGIC_MAP(TESTMAP2, CPPMAGIC_MAP(TESTMAP3, a, b)),
	       "[[ a ]] , [[ b ]]");
	CHECK1(CPPMAGIC_MAP(TESTMAP2, CPPMAGIC_MAP(TESTMAP3, a, b, c)),
	       "[[ a ]] , [[ b ]] , [[ c ]]");
						   
	/* This exits depending on whether all tests passed */
	return exit_status();
}
