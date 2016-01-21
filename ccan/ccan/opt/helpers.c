/* Licensed under GPLv2+ - see LICENSE file for details */
#include <ccan/opt/opt.h>
#include <ccan/cast/cast.h>
#include <inttypes.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include "private.h"
#include <float.h>

/* Upper bound to sprintf this simple type?  Each 3 bits < 1 digit. */
#define CHAR_SIZE(type) (((sizeof(type)*CHAR_BIT + 2) / 3) + 1)

static char *arg_bad(const char *fmt, const char *arg)
{
	char *str = opt_alloc.alloc(strlen(fmt) + strlen(arg));
	sprintf(str, fmt, arg);
	return str;
}

char *opt_set_bool(bool *b)
{
	*b = true;
	return NULL;
}

char *opt_set_invbool(bool *b)
{
	*b = false;
	return NULL;
}

char *opt_set_bool_arg(const char *arg, bool *b)
{
	if (!strcasecmp(arg, "yes") || !strcasecmp(arg, "true"))
		return opt_set_bool(b);
	if (!strcasecmp(arg, "no") || !strcasecmp(arg, "false"))
		return opt_set_invbool(b);

	return opt_invalid_argument(arg);
}

char *opt_set_invbool_arg(const char *arg, bool *b)
{
	char *err = opt_set_bool_arg(arg, b);

	if (!err)
		*b = !*b;
	return err;
}

/* Set a char *. */
char *opt_set_charp(const char *arg, char **p)
{
	*p = cast_const(char *, arg);
	return NULL;
}

/* Set an integer value, various forms.
   FIXME: set to 1 on arg == NULL ? */
char *opt_set_intval(const char *arg, int *i)
{
	long l;
	char *err = opt_set_longval(arg, &l);

	if (err)
		return err;
	*i = l;
	/* Beware truncation, but don't generate untestable code. */
	if (sizeof(*i) != sizeof(l) && *i != l)
		return arg_bad("value '%s' does not fit into an integer", arg);
	return err;
}

char *opt_set_uintval(const char *arg, unsigned int *ui)
{
	int i;
	char *err = opt_set_intval(arg, &i);

	if (err)
		return err;
	if (i < 0)
		return arg_bad("'%s' is negative but destination is unsigned", arg);
	*ui = i;
	return NULL;
}

char *opt_set_longval(const char *arg, long *l)
{
	char *endp;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	*l = strtol(arg, &endp, 0);
	if (*endp || !arg[0])
		return arg_bad("'%s' is not a number", arg);
	if (errno)
		return arg_bad("'%s' is out of range", arg);
	return NULL;
}

char *opt_set_ulongval(const char *arg, unsigned long *ul)
{
	long int l;
	char *err;

	err = opt_set_longval(arg, &l);
	if (err)
		return err;
	*ul = l;
	if (l < 0)
		return arg_bad("'%s' is negative but destination is unsigned", arg);
	return NULL;
}

char *opt_set_floatval(const char *arg, float *f)
{
	double d;
	char *err;

	err = opt_set_doubleval(arg, &d);
	if (err)
		return err;

	*f = d;

	/*allow true infinity via --foo=INF, while avoiding isinf() from math.h
	  because it wasn't standard 25 years ago.*/
	double inf = 1e300 * 1e300; /*direct 1e600 annoys -Woverflow*/
	if ((d > FLT_MAX || d < -FLT_MAX) && d != inf && d != -inf)
		return arg_bad("'%s' is out of range for a 32 bit float", arg);
	if (d != 0 && *f == 0)
		return arg_bad("'%s' is out of range (truncated to zero)", arg);

	return NULL;
}

void opt_show_floatval(char buf[OPT_SHOW_LEN], const float *f)
{
	double d = *f;
	opt_show_doubleval(buf, &d);
}

char *opt_set_doubleval(const char *arg, double *d)
{
	char *endp;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	/* Don't assume strtof */
	*d = strtod(arg, &endp);
	if (*endp || !arg[0])
		return arg_bad("'%s' is not a number", arg);
	if (errno)
		return arg_bad("'%s' is out of range", arg);

	return NULL;
}

void opt_show_doubleval(char buf[OPT_SHOW_LEN], const double *d)
{
	snprintf(buf, OPT_SHOW_LEN, "%f", *d);
}

char *opt_inc_intval(int *i)
{
	(*i)++;
	return NULL;
}

char *opt_dec_intval(int *i)
{
	(*i)--;
	return NULL;
}

/* Display version string. */
char *opt_version_and_exit(const char *version)
{
	printf("%s\n", version);
	/* Don't have valgrind complain! */
	opt_free_table();
	exit(0);
}

char *opt_usage_and_exit(const char *extra)
{
	char *usage = opt_usage(opt_argv0, extra);
	printf("%s", usage);
	/* Don't have valgrind complain! */
	opt_alloc.free(usage);
	opt_free_table();
	exit(0);
}

void opt_show_bool(char buf[OPT_SHOW_LEN], const bool *b)
{
	strncpy(buf, *b ? "true" : "false", OPT_SHOW_LEN);
}

void opt_show_invbool(char buf[OPT_SHOW_LEN], const bool *b)
{
	strncpy(buf, *b ? "false" : "true", OPT_SHOW_LEN);
}

void opt_show_charp(char buf[OPT_SHOW_LEN], char *const *p)
{
	if (*p){
		size_t len = strlen(*p);
		buf[0] = '"';
		if (len > OPT_SHOW_LEN - 2)
			len = OPT_SHOW_LEN - 2;
		strncpy(buf+1, *p, len);
		buf[1+len] = '"';
		if (len < OPT_SHOW_LEN - 2)
			buf[2+len] = '\0';
	}
	else {
		strncpy(buf, "(nil)", OPT_SHOW_LEN);
	}
}

/* Show an integer value, various forms. */
void opt_show_intval(char buf[OPT_SHOW_LEN], const int *i)
{
	snprintf(buf, OPT_SHOW_LEN, "%i", *i);
}

void opt_show_uintval(char buf[OPT_SHOW_LEN], const unsigned int *ui)
{
	snprintf(buf, OPT_SHOW_LEN, "%u", *ui);
}

void opt_show_longval(char buf[OPT_SHOW_LEN], const long *l)
{
	snprintf(buf, OPT_SHOW_LEN, "%li", *l);
}

void opt_show_ulongval(char buf[OPT_SHOW_LEN], const unsigned long *ul)
{
	snprintf(buf, OPT_SHOW_LEN, "%lu", *ul);
}

/* a helper function that multiplies out an argument's kMGTPE suffix in the
 * long long int range, and perform checks common to all integer destinations.
 *
 * The base will be either 1000 or 1024, corresponding with the '_si' and
 * '_bi' functions.
 */

static char *set_llong_with_suffix(const char *arg, long long *ll,
				   const long long base)
{
	char *endp;
	if (!arg[0]){
		*ll = 0;
		return arg_bad("'%s' (an empty string) is not a number", arg);
	}
	errno = 0;
	*ll = strtoll(arg, &endp, 0);
	if (errno)
		return arg_bad("'%s' is out of range", arg);
	if (*endp){
		/*The string continues with non-digits.  If there is just one
		  letter and it is a known multiplier suffix, use it.*/
		if (endp[1])
			return arg_bad("'%s' is not a number (suffix too long)", arg);
		long long mul;
		switch(*endp){
		case 'K':
		case 'k':
			mul = base;
			break;
		case 'M':
		case 'm':
			mul = base * base;
			break;
		case 'G':
		case 'g':
			mul = base * base * base;
			break;
		case 'T':
		case 't':
			mul = base * base * base * base;
			break;
		case 'P':
			mul = base * base * base * base * base;
			break;
		case 'E':
			mul = base * base * base * base * base * base;
			break;
		/* This is as far as we can go in 64 bits ('E' is 2 ^ 60) */
		default:
			return arg_bad("'%s' is not a number (unknown suffix)",
				       arg);
		}
		if (*ll > LLONG_MAX / mul || *ll < LLONG_MIN / mul)
			return arg_bad("'%s' is out of range", arg);
		*ll *= mul;
	}
	return NULL;
}

/* Middle layer helpers that perform bounds checks for specific target sizes
 * and signednesses.
 */
static char * set_ulonglong_with_suffix(const char *arg, unsigned long long *ull,
					const long base)
{
	long long ll;
	char *err = set_llong_with_suffix(arg, &ll, base);
	if (err != NULL)
		return err;
	if (ll < 0)
		return arg_bad("'%s' is negative but destination is unsigned", arg);
	*ull = ll;
	return NULL;
}

static char * set_long_with_suffix(const char *arg, long *l, const long base)
{
	long long ll;
	char *err = set_llong_with_suffix(arg, &ll, base);
	if (err != NULL) /*an error*/
		return err;

	*l = ll;
	/* Beware truncation, but don't generate untestable code. */
	if (sizeof(*l) != sizeof(ll) && *l != ll)
		return arg_bad("value '%s' does not fit into a long", arg);
	return NULL;
}

static char * set_ulong_with_suffix(const char *arg, unsigned long *ul, const long base)
{
	long long ll;
	char *err = set_llong_with_suffix(arg, &ll, base);
	if (err != NULL)
		return err;
	if (ll < 0)
		return arg_bad("'%s' is negative but destination is unsigned", arg);
	*ul = ll;
	/* Beware truncation, but don't generate untestable code. */
	if (sizeof(*ul) != sizeof(ll) && *ul != ll)
		return arg_bad("value '%s' does not fit into an unsigned long", arg);
	return NULL;
}

static char * set_int_with_suffix(const char *arg, int *i, const long base)
{
	long long ll;
	char *err = set_llong_with_suffix(arg, &ll, base);
	if (err != NULL) /*an error*/
		return err;

	*i = ll;
	if (*i != ll)
		return arg_bad("value '%s' does not fit into an int", arg);
	return NULL;
}

static char * set_uint_with_suffix(const char *arg, unsigned int *u, const long base)
{
	long long ll;
	char *err = set_llong_with_suffix(arg, &ll, base);
	if (err != NULL)
		return err;
	if (ll < 0)
		return arg_bad("'%s' is negative but destination is unsigned", arg);
	*u = ll;
	if (*u != ll)
		return arg_bad("value '%s' does not fit into an unsigned int", arg);
	return NULL;
}

/*Set an integer, with decimal or binary suffixes.
  The accepted suffixes are k/K, M/m, G/g, T, P, E.

  The *_bi functions multiply the numeric value by a power of 1024, while the
  *_si functions multiply by a power of 1000.
 */

char * opt_set_ulonglongval_bi(const char *arg, unsigned long long *ll)
{
	return set_ulonglong_with_suffix(arg, ll, 1024);
}

char * opt_set_ulonglongval_si(const char *arg, unsigned long long *ll)
{
	return set_ulonglong_with_suffix(arg, ll, 1000);
}

char * opt_set_longlongval_bi(const char *arg, long long *ll)
{
	return set_llong_with_suffix(arg, ll, 1024);
}

char * opt_set_longlongval_si(const char *arg, long long *ll)
{
	return set_llong_with_suffix(arg, ll, 1000);
}

char * opt_set_longval_bi(const char *arg, long *l)
{
	return set_long_with_suffix(arg, l, 1024);
}

char * opt_set_longval_si(const char *arg, long *l)
{
	return set_long_with_suffix(arg, l, 1000);
}

char * opt_set_ulongval_bi(const char *arg, unsigned long *ul)
{
	return set_ulong_with_suffix(arg, ul, 1024);
}

char * opt_set_ulongval_si(const char *arg, unsigned long *ul)
{
	return set_ulong_with_suffix(arg, ul, 1000);
}

char * opt_set_intval_bi(const char *arg, int *i)
{
	return set_int_with_suffix(arg, i, 1024);
}

char * opt_set_intval_si(const char *arg, int *i)
{
	return set_int_with_suffix(arg, i, 1000);
}

char * opt_set_uintval_bi(const char *arg, unsigned int *u)
{
	return set_uint_with_suffix(arg, u, 1024);
}

char * opt_set_uintval_si(const char *arg, unsigned int *u)
{
	return set_uint_with_suffix(arg, u, 1000);
}

/*static helpers for showing values with kMGTPE suffixes.  In this case there
  are separate but essentially identical functions for signed and unsigned
  values, so that unsigned values greater than LLONG_MAX get suffixes.
 */
static void show_llong_with_suffix(char buf[OPT_SHOW_LEN], long long ll,
				    const long long base)
{
	const char *suffixes = "kMGTPE";
	int i;
	if (ll == 0){
		/*zero is special because everything divides it (you'd get "0E")*/
		snprintf(buf, OPT_SHOW_LEN, "0");
		return;
	}
	for (i = 0; i < strlen(suffixes); i++){
		long long tmp = ll / base;
		if (tmp * base != ll)
			break;
		ll = tmp;
	}
	if (i == 0)
		snprintf(buf, OPT_SHOW_LEN, "%"PRId64, (int64_t)ll);
	else
		snprintf(buf, OPT_SHOW_LEN, "%"PRId64"%c", (int64_t)ll, suffixes[i - 1]);
}

static void show_ullong_with_suffix(char buf[OPT_SHOW_LEN], unsigned long long ull,
				    const unsigned base)
{
	const char *suffixes = "kMGTPE";
	int i;
	if (ull == 0){
		/*zero is special because everything divides it (you'd get "0E")*/
		snprintf(buf, OPT_SHOW_LEN, "0");
		return;
	}
	for (i = 0; i < strlen(suffixes); i++){
		unsigned long long tmp = ull / base;
		if (tmp * base != ull)
			break;
		ull = tmp;
	}
	if (i == 0)
		snprintf(buf, OPT_SHOW_LEN, "%"PRIu64, (uint64_t)ull);
	else
		snprintf(buf, OPT_SHOW_LEN, "%"PRIu64"%c", (uint64_t)ull, suffixes[i - 1]);
}

/* _bi, signed */
void opt_show_intval_bi(char buf[OPT_SHOW_LEN], const int *x)
{
	show_llong_with_suffix(buf, *x, 1024);
}

void opt_show_longval_bi(char buf[OPT_SHOW_LEN], const long *x)
{
	show_llong_with_suffix(buf, *x, 1024);
}

void opt_show_longlongval_bi(char buf[OPT_SHOW_LEN], const long long *x)
{
	show_llong_with_suffix(buf, *x, 1024);
}

/* _bi, unsigned */
void opt_show_uintval_bi(char buf[OPT_SHOW_LEN], const unsigned int *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1024);
}

void opt_show_ulongval_bi(char buf[OPT_SHOW_LEN], const unsigned long *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1024);
}

void opt_show_ulonglongval_bi(char buf[OPT_SHOW_LEN], const unsigned long long *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1024);
}

/* _si, signed */
void opt_show_intval_si(char buf[OPT_SHOW_LEN], const int *x)
{
	show_llong_with_suffix(buf, (long long) *x, 1000);
}

void opt_show_longval_si(char buf[OPT_SHOW_LEN], const long *x)
{
	show_llong_with_suffix(buf, (long long) *x, 1000);
}

void opt_show_longlongval_si(char buf[OPT_SHOW_LEN], const long long *x)
{
	show_llong_with_suffix(buf, *x, 1000);
}

/* _si, unsigned */
void opt_show_uintval_si(char buf[OPT_SHOW_LEN], const unsigned int *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1000);
}

void opt_show_ulongval_si(char buf[OPT_SHOW_LEN], const unsigned long *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1000);
}

void opt_show_ulonglongval_si(char buf[OPT_SHOW_LEN], const unsigned long long *x)
{
	show_ullong_with_suffix(buf, (unsigned long long) *x, 1000);
}

