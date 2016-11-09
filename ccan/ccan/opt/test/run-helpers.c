#include "config.h"
#include <stdio.h>
#include <ccan/tap/tap.h>
#include <setjmp.h>
#include <stdlib.h>
#include <limits.h>
#include "utils.h"
#include <math.h>

/* We don't actually want it to exit... */
static jmp_buf exited;
#define exit(status) longjmp(exited, (status) + 1)

#define printf saved_printf
static int saved_printf(const char *fmt, ...);

#define fprintf saved_fprintf
static int saved_fprintf(FILE *ignored, const char *fmt, ...);

#define vfprintf(f, fmt, ap) saved_vprintf(fmt, ap)
static int saved_vprintf(const char *fmt, va_list ap);

#include <ccan/opt/helpers.c>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/parse.c>

static char *output = NULL;

static int saved_vprintf(const char *fmt, va_list ap)
{
	char *p;
	int ret = vasprintf(&p, fmt, ap);

	if (output) {
		output = realloc(output, strlen(output) + strlen(p) + 1);
		strcat(output, p);
		free(p);
	} else
		output = p;
	return ret;
}

static int saved_printf(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = saved_vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

static int saved_fprintf(FILE *ignored UNNEEDED, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = saved_vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

static void set_args(int *argc, char ***argv, ...)
{
	va_list ap;
	*argv = malloc(sizeof(**argv) * 20);

	va_start(ap, argv);
	for (*argc = 0;
	     ((*argv)[*argc] = va_arg(ap, char*)) != NULL;
	     (*argc)++);
	va_end(ap);
}

/* Test helpers. */
int main(int argc, char *argv[])
{
	plan_tests(500);

	/* opt_set_bool */
	{
		bool arg = false;
		reset_options();
		opt_register_noarg("-a", opt_set_bool, &arg, "");
		ok1(parse_args(&argc, &argv, "-a", NULL));
		ok1(arg);
		opt_register_arg("-b", opt_set_bool_arg, NULL, &arg, "");
		ok1(parse_args(&argc, &argv, "-b", "no", NULL));
		ok1(!arg);
		ok1(parse_args(&argc, &argv, "-b", "yes", NULL));
		ok1(arg);
		ok1(parse_args(&argc, &argv, "-b", "false", NULL));
		ok1(!arg);
		ok1(parse_args(&argc, &argv, "-b", "true", NULL));
		ok1(arg);
		ok1(!parse_args(&argc, &argv, "-b", "unknown", NULL));
		ok1(arg);
		ok1(strstr(err_output, ": -b: Invalid argument 'unknown'"));
	}
	/* opt_set_invbool */
	{
		bool arg = true;
		reset_options();
		opt_register_noarg("-a", opt_set_invbool, &arg, "");
		ok1(parse_args(&argc, &argv, "-a", NULL));
		ok1(!arg);
		opt_register_arg("-b", opt_set_invbool_arg, NULL,
				 &arg, "");
		ok1(parse_args(&argc, &argv, "-b", "no", NULL));
		ok1(arg);
		ok1(parse_args(&argc, &argv, "-b", "yes", NULL));
		ok1(!arg);
		ok1(parse_args(&argc, &argv, "-b", "false", NULL));
		ok1(arg);
		ok1(parse_args(&argc, &argv, "-b", "true", NULL));
		ok1(!arg);
		ok1(!parse_args(&argc, &argv, "-b", "unknown", NULL));
		ok1(!arg);
		ok1(strstr(err_output, ": -b: Invalid argument 'unknown'"));
	}
	/* opt_set_charp */
	{
		char *arg = cast_const(char *, "wrong");
		reset_options();
		opt_register_arg("-a", opt_set_charp, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "string", NULL));
		ok1(strcmp(arg, "string") == 0);
	}
	/* opt_set_intval */
	{
		int arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_intval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(arg == -9999);
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		if (sizeof(int) == 4)
			ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
		else
			fail("Handle other int sizes");
	}
	/* opt_set_uintval */
	{
		unsigned int arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_uintval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
		if (ULONG_MAX == UINT_MAX) {
			pass("Can't test overflow");
			pass("Can't test error message");
		} else {
			char buf[30];
			sprintf(buf, "%lu", ULONG_MAX);
			ok1(!parse_args(&argc, &argv, "-a", buf, NULL));
			ok1(strstr(err_output, ": -a: value '")
			    && strstr(err_output, buf)
			    && strstr(err_output, "' does not fit into an integer"));
		}
	}
	/* opt_set_longval */
	{
		long int arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_longval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(arg == -9999);
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		if (sizeof(long) == 4)
			ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
		else if (sizeof(long)== 8)
			ok1(!parse_args(&argc, &argv, "-a", "18446744073709551616", NULL));
		else
			fail("FIXME: Handle other long sizes");
	}
	/* opt_set_ulongval */
	{
		unsigned long int arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_ulongval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		if (sizeof(long) == 4)
			ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
		else if (sizeof(long)== 8)
			ok1(!parse_args(&argc, &argv, "-a", "18446744073709551616", NULL));
		else
			fail("FIXME: Handle other long sizes");
	}
	/* opt_set_floatval */
	{
		float arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_floatval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(arg == -9999);
		ok1(parse_args(&argc, &argv, "-a", "1e33", NULL));
		ok1(arg == 1e33f);
		/*overflows should fail */
		ok1(!parse_args(&argc, &argv, "-a", "1e39", NULL));
		ok1(!parse_args(&argc, &argv, "-a", "-1e40", NULL));
		/*low numbers lose precision but work */
		ok1(parse_args(&argc, &argv, "-a", "1e-39", NULL));
		ok1(arg == 1e-39f);
		ok1(parse_args(&argc, &argv, "-a", "-1e-45", NULL));
		ok1(arg == -1e-45f);
		ok1(!parse_args(&argc, &argv, "-a", "1e-99", NULL));
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(parse_args(&argc, &argv, "-a", "1.111111111111", NULL));
		ok1(arg == 1.1111112f);
		ok1(parse_args(&argc, &argv, "-a", "INF", NULL));
		ok1(isinf(arg));
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		ok1(!parse_args(&argc, &argv, "-a", "1e7crap", NULL));
	}
	/* opt_set_doubleval */
	{
		double arg = 1000;
		reset_options();
		opt_register_arg("-a", opt_set_doubleval, NULL, &arg, "All");
		ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
		ok1(arg == 9999);
		ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
		ok1(arg == -9999);
		ok1(parse_args(&argc, &argv, "-a", "1e-299", NULL));
		ok1(arg == 1e-299);
		ok1(parse_args(&argc, &argv, "-a", "-1e-305", NULL));
		ok1(arg == -1e-305);
		ok1(!parse_args(&argc, &argv, "-a", "1e-499", NULL));
		ok1(parse_args(&argc, &argv, "-a", "0", NULL));
		ok1(arg == 0);
		ok1(parse_args(&argc, &argv, "-a", "1.1111111111111111111", NULL));
		ok1(arg == 1.1111111111111112);
		ok1(parse_args(&argc, &argv, "-a", "INF", NULL));
		ok1(isinf(arg));
		ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
		ok1(!parse_args(&argc, &argv, "-a", "1e7crap", NULL));
	}

	{
		const long long k = 1024;
		const long long M = k * k;
		const long long G = k * k * k;
		const long long T = k * k * k * k;
		const long long P = k * k * k * k * k;
		const long long E = k * k * k * k * k * k;

		/* opt_set_uintval_bi */
		{
			unsigned int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_uintval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0k", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "3Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "30k", NULL));
			ok1(arg == 30 * k);
			ok1(!parse_args(&argc, &argv, "-a", "-1K", NULL));
	}

		/* opt_set_intval_bi */
		{
			int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_intval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0k", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "3Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "30k", NULL));
			ok1(arg == 30 * k);
			ok1(parse_args(&argc, &argv, "-a", "-1K", NULL));
			ok1(arg == -1 * k);
		}


		/* opt_set_ulongval_bi */
		{
			unsigned long int arg = 1000;

			reset_options();
			opt_register_arg("-a", opt_set_ulongval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "99M", NULL));
			ok1(arg == 99 * M);
			/*note, 2999M > max signed 32 bit long, 1 << 31*/
			ok1(parse_args(&argc, &argv, "-a", "2999m", NULL));
			ok1(arg == 2999 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(!parse_args(&argc, &argv, "-a", "-1G", NULL));
			if (sizeof(long) == 4){
				ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1T", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
			}
			else if (sizeof(long) == 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"18446744073709551616", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "8E", NULL));
				ok1(parse_args(&argc, &argv, "-a", "3E", NULL));
			}
			else
				fail("FIXME: Handle other long sizes");
		}

		/* opt_set_longval_bi */
		{
			long int arg = 1000;

			reset_options();
			opt_register_arg("-a", opt_set_longval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "-100k", NULL));
			ok1(arg == -100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "99M", NULL));
			ok1(arg == 99 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(parse_args(&argc, &argv, "-a", "-1G", NULL));
			ok1(arg == -1 * G);
			if (sizeof(long) == 4){
				ok1(!parse_args(&argc, &argv, "-a", "2147483648", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "2G", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "2048m", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1T", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
			}
			else if (sizeof(long) == 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"9223372036854775808", NULL));
				ok1(parse_args(&argc, &argv, "-a", "3E", NULL));
				ok1(arg == 3 * E);
				ok1(parse_args(&argc, &argv, "-a", "123T", NULL));
				ok1(arg == 123 * T);
			}
			else
				fail("FIXME: Handle other long sizes");
		}


		/* opt_set_longlongval_bi */
		{
			long long int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_longlongval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1kk", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "-100k", NULL));
			ok1(arg == -100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "-333333M", NULL));
			ok1(arg == -333333 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(parse_args(&argc, &argv, "-a", "1024t", NULL));
			ok1(arg == 1024 * T);
			ok1(parse_args(&argc, &argv, "-a", "123P", NULL));
			ok1(arg == 123 * P);
			ok1(parse_args(&argc, &argv, "-a", "-3E", NULL));
			ok1(arg == -3 * E);

			if (sizeof(long long) == 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"9223372036854775808", NULL));
				/*8E and 922337.. are both 1 << 63*/
				ok1(!parse_args(&argc, &argv, "-a", "8E", NULL));
			}
			else
				fail("FIXME: Handle other long long int"
				     " sizes (specifically %zu bytes)",
				     sizeof(long long));
		}
		/* opt_set_ulonglongval_bi */
		{
			unsigned long long int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_ulonglongval_bi, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1kk", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100G", NULL));
			ok1(arg == 100 * G);
			ok1(!parse_args(&argc, &argv, "-a", "-100G", NULL));
			ok1(parse_args(&argc, &argv, "-a", "8191P", NULL));
			ok1(arg == 8191 * P);
		}

		/* opt_show_intval_bi */
		{
			int i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -77;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "-77") == 0);
			i = 0;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 77;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -1234 * k;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "-1234k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * M;
			opt_show_intval_bi(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_longval_bi */
		{
			long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -77;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "-77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 77;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -1 * k;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "-1k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * M;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 0;
			opt_show_longval_bi(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_llongval_bi */
		{
			long long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -7777;
			opt_show_longlongval_bi(buf, &i);
			ok1(strcmp(buf, "-7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 7777;
			opt_show_longlongval_bi(buf, &i);
			ok1(strcmp(buf, "7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -10240000 * k;
			opt_show_longlongval_bi(buf, &i);
			ok1(strcmp(buf, "-10000M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 5 * P;
			opt_show_longlongval_bi(buf, &i);
			ok1(strcmp(buf, "5P") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * P;
			opt_show_longlongval_bi(buf, &i);
			ok1(strcmp(buf, "1E") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_uintval_bi */
		{
			unsigned int i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 77;
			opt_show_uintval_bi(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1234 * k;
			opt_show_uintval_bi(buf, &i);
			ok1(strcmp(buf, "1234k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_uintval_bi(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * M;
			opt_show_uintval_bi(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_ulongval_bi */
		{
			unsigned long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 77;
			opt_show_ulongval_bi(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = k;
			opt_show_ulongval_bi(buf, &i);
			ok1(strcmp(buf, "1k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_ulongval_bi(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * M;
			opt_show_ulongval_bi(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 0;
			opt_show_ulongval_bi(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_ullongval_bi */
		{
			long long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 7777;
			opt_show_ulonglongval_bi(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 10240000 * k;
			opt_show_ulonglongval_bi(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "10000M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 5 * P;
			opt_show_ulonglongval_bi(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "5P") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * P;
			opt_show_ulonglongval_bi(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "1E") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}
	}

	{
		const long long k = 1000;
		const long long M = k * k;
		const long long G = k * k * k;
		const long long T = k * k * k * k;
		const long long P = k * k * k * k * k;
		const long long E = k * k * k * k * k * k;

		/* opt_set_uintval_si */
		{
			unsigned int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_uintval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0k", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "3Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "30k", NULL));
			ok1(arg == 30 * k);
			ok1(!parse_args(&argc, &argv, "-a", "-1K", NULL));
			if (sizeof(unsigned int) < 8)
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
			else
				pass("can't test int truncation when int is so huge");
	}

		/* opt_set_intval_si */
		{
			int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_intval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0k", NULL));
			ok1(arg == 0);
			arg = 1;
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "3Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "30k", NULL));
			ok1(arg == 30 * k);
			ok1(parse_args(&argc, &argv, "-a", "-1K", NULL));
			ok1(arg == -1 * k);
			if (sizeof(int) < 8)
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
			else
				pass("can't test int truncation when int is so huge");
		}


		/* opt_set_ulongval_si */
		{
			unsigned long int arg = 1000;

			reset_options();
			opt_register_arg("-a", opt_set_ulongval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "99M", NULL));
			ok1(arg == 99 * M);
			/*note, 2999M > max signed 32 bit long, 1 << 31*/
			ok1(parse_args(&argc, &argv, "-a", "2999m", NULL));
			ok1(arg == 2999 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(!parse_args(&argc, &argv, "-a", "-1G", NULL));
			ok1(parse_args(&argc, &argv, "-a", "4G", NULL));
			ok1(arg == 4000000000U);
			if (sizeof(long) == 4){
				ok1(!parse_args(&argc, &argv, "-a", "4294967296", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "4295M", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1T", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
			}
			else if (sizeof(long)== 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"18446744073709551616", NULL));
				ok1(parse_args(&argc, &argv, "-a", "9E", NULL));
				ok1(arg == 9000000000000000000ULL);
				ok1(!parse_args(&argc, &argv, "-a", "19E", NULL));
			}
			else
				fail("FIXME: Handle other long sizes");
		}

		/* opt_set_longval_si */
		{
			long int arg = 1000;

			reset_options();
			opt_register_arg("-a", opt_set_longval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0P", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "-100k", NULL));
			ok1(arg == -100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "99M", NULL));
			ok1(arg == 99 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(parse_args(&argc, &argv, "-a", "-1G", NULL));
			ok1(arg == -1 * G);
			if (sizeof(long) == 4){
				ok1(!parse_args(&argc, &argv, "-a", "2147483648", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "4G", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1T", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "1E", NULL));
				ok1(parse_args(&argc, &argv, "-a", "1999m", NULL));
				ok1(arg == 1999 * M);
			}
			else if (sizeof(long)== 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"9223372036854775808", NULL));
				ok1(!parse_args(&argc, &argv, "-a", "9224P", NULL));
				ok1(parse_args(&argc, &argv, "-a", "9E", NULL));
				ok1(arg == 9 * E);
				ok1(parse_args(&argc, &argv, "-a", "123T", NULL));
				ok1(arg == 123 * T);
			}
			else
				fail("FIXME: Handle other long sizes");
		}


		/* opt_set_longlongval_si */
		{
			long long int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_longlongval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(arg == -9999);
			ok1(parse_args(&argc, &argv, "-a", "0T", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "100crap", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1kk", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100k", NULL));
			ok1(arg == 100 * k);
			ok1(parse_args(&argc, &argv, "-a", "-100k", NULL));
			ok1(arg == -100 * k);
			ok1(parse_args(&argc, &argv, "-a", "1K", NULL));
			ok1(arg == 1 * k);
			ok1(parse_args(&argc, &argv, "-a", "-333333M", NULL));
			ok1(arg == -333333 * M);
			ok1(parse_args(&argc, &argv, "-a", "1G", NULL));
			ok1(arg == 1 * G);
			ok1(parse_args(&argc, &argv, "-a", "1024t", NULL));
			ok1(arg == 1024 * T);
			ok1(parse_args(&argc, &argv, "-a", "123P", NULL));
			ok1(arg == 123 * P);
			ok1(parse_args(&argc, &argv, "-a", "-3E", NULL));
			ok1(arg == -3 * E);
			ok1(parse_args(&argc, &argv, "-a", "8E", NULL));
			if (sizeof(long long) == 8){
				ok1(!parse_args(&argc, &argv, "-a",
						"9223372036854775808", NULL));
				ok1(!parse_args(&argc, &argv, "-a",
						"10E", NULL));
			}
			else
				fail("FIXME: Handle other long long int"
				     " sizes (specifically %zu bytes)",
				     sizeof(long long));

		}
		/* opt_set_ulonglongval_si */
		{
			unsigned long long int arg = 1000;
			reset_options();
			opt_register_arg("-a", opt_set_ulonglongval_si, NULL,
					 &arg, "All");
			ok1(parse_args(&argc, &argv, "-a", "9999", NULL));
			ok1(arg == 9999);
			ok1(!parse_args(&argc, &argv, "-a", "-9999", NULL));
			ok1(parse_args(&argc, &argv, "-a", "0", NULL));
			ok1(arg == 0);
			ok1(!parse_args(&argc, &argv, "-a", "1Q", NULL));
			ok1(!parse_args(&argc, &argv, "-a", "1kk", NULL));
			ok1(parse_args(&argc, &argv, "-a", "100G", NULL));
			ok1(arg == 100 * G);
			ok1(!parse_args(&argc, &argv, "-a", "-100G", NULL));
			ok1(parse_args(&argc, &argv, "-a", "8E", NULL));
		}
		/* opt_show_intval_si */
		{
			int i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -77;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "-77") == 0);
			i = 0;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 77;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -1234 * k;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "-1234k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1000 * M;
			opt_show_intval_si(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_longval_si */
		{
			long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -77;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "-77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 77;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -1 * k;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "-1k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1000 * M;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 0;
			opt_show_longval_si(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_llongval_si */
		{
			long long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = -7777;
			opt_show_longlongval_si(buf, &i);
			ok1(strcmp(buf, "-7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 7777;
			opt_show_longlongval_si(buf, &i);
			ok1(strcmp(buf, "7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = -10240000 * k;
			opt_show_longlongval_si(buf, &i);
			ok1(strcmp(buf, "-10240M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 5 * P;
			opt_show_longlongval_si(buf, &i);
			ok1(strcmp(buf, "5P") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 2000 * P;
			opt_show_longlongval_si(buf, &i);
			ok1(strcmp(buf, "2E") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_uintval_si */
		{
			unsigned int i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 77;
			opt_show_uintval_si(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1234 * k;
			opt_show_uintval_si(buf, &i);
			ok1(strcmp(buf, "1234k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_uintval_si(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1000 * M;
			opt_show_uintval_si(buf, &i);
			ok1(strcmp(buf, "1G") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_ulongval_si */
		{
			unsigned long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 77;
			opt_show_ulongval_si(buf, &i);
			ok1(strcmp(buf, "77") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = k;
			opt_show_ulongval_si(buf, &i);
			ok1(strcmp(buf, "1k") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 500 * M;
			opt_show_ulongval_si(buf, &i);
			ok1(strcmp(buf, "500M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1024 * M;
			opt_show_ulongval_si(buf, &i);
			ok1(strcmp(buf, "1024M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 0;
			opt_show_ulongval_si(buf, &i);
			ok1(strcmp(buf, "0") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

		/* opt_show_ullongval_si */
		{
			long long i;
			char buf[OPT_SHOW_LEN+2] = { 0 };
			buf[OPT_SHOW_LEN] = '!';
			i = 7777;
			opt_show_ulonglongval_si(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "7777") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 10240000 * k;
			opt_show_ulonglongval_si(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "10240M") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 5 * P;
			opt_show_ulonglongval_si(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "5P") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
			i = 1000 * P;
			opt_show_ulonglongval_si(buf, (unsigned long long *)&i);
			ok1(strcmp(buf, "1E") == 0);
			ok1(buf[OPT_SHOW_LEN] == '!');
		}

	}


	/* opt_inc_intval */
	{
		int arg = 1000;
		reset_options();
		opt_register_noarg("-a", opt_inc_intval, &arg, "");
		ok1(parse_args(&argc, &argv, "-a", NULL));
		ok1(arg == 1001);
		ok1(parse_args(&argc, &argv, "-a", "-a", NULL));
		ok1(arg == 1003);
		ok1(parse_args(&argc, &argv, "-aa", NULL));
		ok1(arg == 1005);
	}

	/* opt_show_version_and_exit. */
	{
		int exitval;
		reset_options();
		opt_register_noarg("-a",
				   opt_version_and_exit, "1.2.3", "");
		/* parse_args allocates argv */
		free(argv);

		set_args(&argc, &argv, "thisprog", "-a", NULL);

		exitval = setjmp(exited);
		if (exitval == 0) {
			opt_parse(&argc, argv, save_err_output);
			fail("opt_show_version_and_exit returned?");
		} else {
			ok1(exitval - 1 == 0);
			/* We should have freed table!. */
			ok1(opt_table == NULL);
		}
		ok1(strcmp(output, "1.2.3\n") == 0);
		free(output);
		free(argv);
		output = NULL;
	}

	/* opt_usage_and_exit. */
	{
		int exitval;
		reset_options();
		opt_register_noarg("-a",
				   opt_usage_and_exit, "[args]", "");

		set_args(&argc, &argv, "thisprog", "-a", NULL);

		exitval = setjmp(exited);
		if (exitval == 0) {
			opt_parse(&argc, argv, save_err_output);
			fail("opt_usage_and_exit returned?");
		} else {
			ok1(exitval - 1 == 0);
			/* We should have freed table!. */
			ok1(opt_table == NULL);
		}
		ok1(strstr(output, "[args]"));
		ok1(strstr(output, argv[0]));
		ok1(strstr(output, "\n-a"));
		free(output);
		free(argv);
		output = NULL;
	}

	/* opt_show_bool */
	{
		bool b;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		b = true;
		opt_show_bool(buf, &b);
		ok1(strcmp(buf, "true") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		b = false;
		opt_show_bool(buf, &b);
		ok1(strcmp(buf, "false") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_invbool */
	{
		bool b;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		b = true;
		opt_show_invbool(buf, &b);
		ok1(strcmp(buf, "false") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		b = false;
		opt_show_invbool(buf, &b);
		ok1(strcmp(buf, "true") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_charp */
	{
		char str[OPT_SHOW_LEN*2], *p;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		/* Short test. */
		p = str;
		strcpy(p, "short");
		opt_show_charp(buf, &p);
		ok1(strcmp(buf, "\"short\"") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		/* Truncate test. */
		memset(p, 'x', OPT_SHOW_LEN*2);
		p[OPT_SHOW_LEN*2-1] = '\0';
		opt_show_charp(buf, &p);
		ok1(buf[0] == '"');
		ok1(buf[OPT_SHOW_LEN-1] == '"');
		ok1(buf[OPT_SHOW_LEN] == '!');
		ok1(strspn(buf+1, "x") == OPT_SHOW_LEN-2);
	}

	/* opt_show_intval */
	{
		int i;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		i = -77;
		opt_show_intval(buf, &i);
		ok1(strcmp(buf, "-77") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		i = 77;
		opt_show_intval(buf, &i);
		ok1(strcmp(buf, "77") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_uintval */
	{
		unsigned int ui;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		ui = 4294967295U;
		opt_show_uintval(buf, &ui);
		ok1(strcmp(buf, "4294967295") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_longval */
	{
		long l;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		l = 1234567890L;
		opt_show_longval(buf, &l);
		ok1(strcmp(buf, "1234567890") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_ulongval */
	{
		unsigned long ul;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		ul = 4294967295UL;
		opt_show_ulongval(buf, &ul);
		ok1(strcmp(buf, "4294967295") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_floatval */
	{
		float f;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		f = -77.5;
		opt_show_floatval(buf, &f);
		ok1(strcmp(buf, "-77.500000") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		f = 77.5;
		opt_show_floatval(buf, &f);
		ok1(strcmp(buf, "77.500000") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_show_doubleval */
	{
		double d;
		char buf[OPT_SHOW_LEN+2] = { 0 };
		buf[OPT_SHOW_LEN] = '!';

		d = -77;
		opt_show_doubleval(buf, &d);
		ok1(strcmp(buf, "-77.000000") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');

		d = 77;
		opt_show_doubleval(buf, &d);
		ok1(strcmp(buf, "77.000000") == 0);
		ok1(buf[OPT_SHOW_LEN] == '!');
	}

	/* opt_log_stderr. */
	{
		reset_options();
		opt_register_noarg("-a",
				   opt_usage_and_exit, "[args]", "");

		set_args(&argc, &argv, "thisprog", "--garbage", NULL);
		ok1(!opt_parse(&argc, argv, opt_log_stderr));
		ok1(!strcmp(output,
			    "thisprog: --garbage: unrecognized option\n"));
		free(output);
		free(argv);
		output = NULL;
	}

	/* opt_log_stderr_exit. */
	{
		int exitval;
		reset_options();
		opt_register_noarg("-a",
				   opt_usage_and_exit, "[args]", "");
		set_args(&argc, &argv, "thisprog", "--garbage", NULL);
		exitval = setjmp(exited);
		if (exitval == 0) {
			opt_parse(&argc, argv, opt_log_stderr_exit);
			fail("opt_log_stderr_exit returned?");
		} else {
			ok1(exitval - 1 == 1);
		}
		free(argv);
		ok1(!strcmp(output,
			    "thisprog: --garbage: unrecognized option\n"));
		free(output);
		output = NULL;
	}

	//diag("%s\n", err_output);
	return exit_status();
}
