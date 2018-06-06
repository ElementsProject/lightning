/* Simple tool to create config.h.
 * Would be much easier with ccan modules, but deliberately standalone.
 *
 * Copyright 2011 Rusty Russell <rusty@rustcorp.com.au>.  MIT license.
 *
 * c12r_err, c12r_errx functions copied from ccan/err/err.c
 * Copyright Rusty Russell <rusty@rustcorp.com.au>. CC0 (Public domain) License.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#define _POSIX_C_SOURCE 200809L                /* For pclose, popen, strdup */

#define EXIT_BAD_USAGE		  1
#define EXIT_TROUBLE_RUNNING	  2
#define EXIT_BAD_TEST		  3
#define EXIT_BAD_INPUT		  4

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _MSC_VER
#define popen _popen
#define pclose _pclose
#endif

#ifdef _MSC_VER
#define DEFAULT_COMPILER "cl"
/* Note:  Dash options avoid POSIX path conversion when used under msys bash
 *        and are therefore preferred to slash (e.g. -nologo over /nologo)
 * Note:  Disable Warning 4200 "nonstandard extension used : zero-sized array
 *        in struct/union" for flexible array members.
 */
#define DEFAULT_FLAGS "-nologo -Zi -W4 -wd4200 " \
	"-D_CRT_NONSTDC_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS"
#define DEFAULT_OUTPUT_EXE_FLAG "-Fe:"
#else
#define DEFAULT_COMPILER "cc"
#define DEFAULT_FLAGS "-g3 -ggdb -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition"
#define DEFAULT_OUTPUT_EXE_FLAG "-o"
#endif

#define OUTPUT_FILE "configurator.out"
#define INPUT_FILE "configuratortest.c"

#ifdef _WIN32
#define DIR_SEP   "\\"
#else
#define DIR_SEP   "/"
#endif

static const char *progname = "";
static int verbose;
static bool like_a_libtool = false;

struct test {
	const char *name;
	const char *desc;
	/*
	 * Template style flags (pick one):
	 * OUTSIDE_MAIN:
	 * - put a simple boilerplate main below it.
	 * DEFINES_FUNC:
	 * - defines a static function called func; adds ref to avoid warnings
	 * INSIDE_MAIN:
	 * - put this inside main().
	 * DEFINES_EVERYTHING:
	 * - don't add any boilerplate at all.
	 *
	 * Execution flags:
	 * EXECUTE:
	 * - a runtime test; must compile, exit 0 means flag is set.
	 * MAY_NOT_COMPILE:
	 * - Only useful with EXECUTE: don't get upset if it doesn't compile.
	 * <nothing>:
	 * - a compile test, if it compiles must run and exit 0.
	 */
	const char *style;
	const char *depends;
	const char *link;
	const char *fragment;
	const char *flags;
	const char *overrides; /* On success, force this to '1' */
	bool done;
	bool answer;
};

/* Terminated by a NULL name */
static struct test *tests;

static const struct test base_tests[] = {
	{ "HAVE_32BIT_OFF_T", "off_t is 32 bits",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "int main(void) {\n"
	  "	return sizeof(off_t) == 4 ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_ALIGNOF", "__alignof__ support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __alignof__(double) > 0 ? 0 : 1;" },
	{ "HAVE_ASPRINTF", "asprintf() declaration",
	  "DEFINES_FUNC", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <stdio.h>\n"
	  "static char *func(int x) {"
	  "	char *p;\n"
	  "	if (asprintf(&p, \"%u\", x) == -1) \n"
	  "		p = NULL;\n"
	  "	return p;\n"
	  "}" },
	{ "HAVE_ATTRIBUTE_COLD", "__attribute__((cold)) support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static int __attribute__((cold)) func(int x) { return x; }" },
	{ "HAVE_ATTRIBUTE_CONST", "__attribute__((const)) support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static int __attribute__((const)) func(int x) { return x; }" },
	{ "HAVE_ATTRIBUTE_PURE", "__attribute__((pure)) support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static int __attribute__((pure)) func(int x) { return x; }" },
	{ "HAVE_ATTRIBUTE_MAY_ALIAS", "__attribute__((may_alias)) support",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "typedef short __attribute__((__may_alias__)) short_a;" },
	{ "HAVE_ATTRIBUTE_NORETURN", "__attribute__((noreturn)) support",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <stdlib.h>\n"
	  "static void __attribute__((noreturn)) func(int x) { exit(x); }" },
	{ "HAVE_ATTRIBUTE_PRINTF", "__attribute__ format printf support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static void __attribute__((format(__printf__, 1, 2))) func(const char *fmt, ...) { (void)fmt; }" },
	{ "HAVE_ATTRIBUTE_UNUSED", "__attribute__((unused)) support",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "static int __attribute__((unused)) func(int x) { return x; }" },
	{ "HAVE_ATTRIBUTE_USED", "__attribute__((used)) support",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "static int __attribute__((used)) func(int x) { return x; }" },
	{ "HAVE_BACKTRACE", "backtrace() in <execinfo.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <execinfo.h>\n"
	  "static int func(int x) {"
	  "	void *bt[10];\n"
	  "	return backtrace(bt, 10) < x;\n"
	  "}" },
	{ "HAVE_BIG_ENDIAN", "big endian",
	  "INSIDE_MAIN|EXECUTE", NULL, NULL,
	  "union { int i; char c[sizeof(int)]; } u;\n"
	  "u.i = 0x01020304;\n"
	  "return u.c[0] == 0x01 && u.c[1] == 0x02 && u.c[2] == 0x03 && u.c[3] == 0x04 ? 0 : 1;" },
	{ "HAVE_BSWAP_64", "bswap64 in byteswap.h",
	  "DEFINES_FUNC", "HAVE_BYTESWAP_H", NULL,
	  "#include <byteswap.h>\n"
	  "static int func(int x) { return bswap_64(x); }" },
	{ "HAVE_BUILTIN_CHOOSE_EXPR", "__builtin_choose_expr support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_choose_expr(1, 0, \"garbage\");" },
	{ "HAVE_BUILTIN_CLZ", "__builtin_clz support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_clz(1) == (sizeof(int)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CLZL", "__builtin_clzl support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_clzl(1) == (sizeof(long)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CLZLL", "__builtin_clzll support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_clzll(1) == (sizeof(long long)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CTZ", "__builtin_ctz support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ctz(1 << (sizeof(int)*8 - 1)) == (sizeof(int)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CTZL", "__builtin_ctzl support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ctzl(1UL << (sizeof(long)*8 - 1)) == (sizeof(long)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CTZLL", "__builtin_ctzll support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ctzll(1ULL << (sizeof(long long)*8 - 1)) == (sizeof(long long)*8 - 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_CONSTANT_P", "__builtin_constant_p support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_constant_p(1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_EXPECT", "__builtin_expect support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_expect(argc == 1, 1) ? 0 : 1;" },
	{ "HAVE_BUILTIN_FFS", "__builtin_ffs support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ffs(0) == 0 ? 0 : 1;" },
	{ "HAVE_BUILTIN_FFSL", "__builtin_ffsl support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ffsl(0L) == 0 ? 0 : 1;" },
	{ "HAVE_BUILTIN_FFSLL", "__builtin_ffsll support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_ffsll(0LL) == 0 ? 0 : 1;" },
	{ "HAVE_BUILTIN_POPCOUNT", "__builtin_popcount support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_popcount(255) == 8 ? 0 : 1;" },
	{ "HAVE_BUILTIN_POPCOUNTL",  "__builtin_popcountl support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_popcountl(255L) == 8 ? 0 : 1;" },
	{ "HAVE_BUILTIN_POPCOUNTLL", "__builtin_popcountll support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_popcountll(255LL) == 8 ? 0 : 1;" },
	{ "HAVE_BUILTIN_TYPES_COMPATIBLE_P", "__builtin_types_compatible_p support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return __builtin_types_compatible_p(char *, int) ? 1 : 0;" },
	{ "HAVE_ICCARM_INTRINSICS", "<intrinsics.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <intrinsics.h>\n"
	  "int func(int v) {\n"
	  "	return __CLZ(__RBIT(v));\n"
	  "}" },
	{ "HAVE_BYTESWAP_H", "<byteswap.h>",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "#include <byteswap.h>\n" },
	{ "HAVE_CLOCK_GETTIME", "clock_gettime() declaration",
	  "DEFINES_FUNC", "HAVE_STRUCT_TIMESPEC", NULL,
	  "#include <time.h>\n"
	  "static struct timespec func(void) {\n"
	  "	struct timespec ts;\n"
	  "	clock_gettime(CLOCK_REALTIME, &ts);\n"
	  "	return ts;\n"
	  "}\n" },
	{ "HAVE_CLOCK_GETTIME_IN_LIBRT", "clock_gettime() in librt",
	  "DEFINES_FUNC",
	  "HAVE_STRUCT_TIMESPEC !HAVE_CLOCK_GETTIME",
	  "-lrt",
	  "#include <time.h>\n"
	  "static struct timespec func(void) {\n"
	  "	struct timespec ts;\n"
	  "	clock_gettime(CLOCK_REALTIME, &ts);\n"
	  "	return ts;\n"
	  "}\n",
	  /* This means HAVE_CLOCK_GETTIME, too */
	  "HAVE_CLOCK_GETTIME" },
	{ "HAVE_COMPOUND_LITERALS", "compound literal support",
	  "INSIDE_MAIN", NULL, NULL,
	  "int *foo = (int[]) { 1, 2, 3, 4 };\n"
	  "return foo[0] ? 0 : 1;" },
	{ "HAVE_FCHDIR", "fchdir support",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <sys/stat.h>\n"
	  "#include <fcntl.h>\n"
	  "#include <unistd.h>\n"
	  "int main(void) {\n"
	  "	int fd = open(\"..\", O_RDONLY);\n"
	  "	return fchdir(fd) == 0 ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_ERR_H", "<err.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <err.h>\n"
	  "static void func(int arg) {\n"
	  "	if (arg == 0)\n"
	  "		err(1, \"err %u\", arg);\n"
	  "	if (arg == 1)\n"
	  "		errx(1, \"err %u\", arg);\n"
	  "	if (arg == 3)\n"
	  "		warn(\"warn %u\", arg);\n"
	  "	if (arg == 4)\n"
	  "		warnx(\"warn %u\", arg);\n"
	  "}\n" },
	{ "HAVE_FILE_OFFSET_BITS", "_FILE_OFFSET_BITS to get 64-bit offsets",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE",
	  "HAVE_32BIT_OFF_T", NULL,
	  "#define _FILE_OFFSET_BITS 64\n"
	  "#include <sys/types.h>\n"
	  "int main(void) {\n"
	  "	return sizeof(off_t) == 8 ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_FOR_LOOP_DECLARATION", "for loop declaration support",
	  "INSIDE_MAIN", NULL, NULL,
	  "int ret = 1;\n"
	  "for (int i = 0; i < argc; i++) { ret = 0; };\n"
	  "return ret;" },
	{ "HAVE_FLEXIBLE_ARRAY_MEMBER", "flexible array member support",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "struct foo { unsigned int x; int arr[]; };" },
	{ "HAVE_GETPAGESIZE", "getpagesize() in <unistd.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <unistd.h>\n"
	  "static int func(void) { return getpagesize(); }" },
	{ "HAVE_ISBLANK", "isblank() in <ctype.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <ctype.h>\n"
	  "static int func(void) { return isblank(' '); }" },
	{ "HAVE_LITTLE_ENDIAN", "little endian",
	  "INSIDE_MAIN|EXECUTE", NULL, NULL,
	  "union { int i; char c[sizeof(int)]; } u;\n"
	  "u.i = 0x01020304;\n"
	  "return u.c[0] == 0x04 && u.c[1] == 0x03 && u.c[2] == 0x02 && u.c[3] == 0x01 ? 0 : 1;" },
	{ "HAVE_MEMMEM", "memmem in <string.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <string.h>\n"
	  "static void *func(void *h, size_t hl, void *n, size_t nl) {\n"
	  "return memmem(h, hl, n, nl);"
	  "}\n", },
	{ "HAVE_MEMRCHR", "memrchr in <string.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <string.h>\n"
	  "static void *func(void *s, int c, size_t n) {\n"
	  "return memrchr(s, c, n);"
	  "}\n", },
	{ "HAVE_MMAP", "mmap() declaration",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <sys/mman.h>\n"
	  "static void *func(int fd) {\n"
	  "	return mmap(0, 65536, PROT_READ, MAP_SHARED, fd, 0);\n"
	  "}" },
	{ "HAVE_PROC_SELF_MAPS", "/proc/self/maps exists",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <sys/stat.h>\n"
	  "#include <fcntl.h>\n"
	  "int main(void) {\n"
	  "	return open(\"/proc/self/maps\", O_RDONLY) != -1 ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_QSORT_R_PRIVATE_LAST", "qsort_r cmp takes trailing arg",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <stdlib.h>\n"
	  "static int cmp(const void *lp, const void *rp, void *priv) {\n"
	  " *(unsigned int *)priv = 1;\n"
	  " return *(const int *)lp - *(const int *)rp; }\n"
	  "int main(void) {\n"
	  " int array[] = { 9, 2, 5 };\n"
	  " unsigned int called = 0;\n"
	  " qsort_r(array, 3, sizeof(int), cmp, &called);\n"
	  " return called && array[0] == 2 && array[1] == 5 && array[2] == 9 ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_STRUCT_TIMESPEC", "struct timespec declaration",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <time.h>\n"
	  "static void func(void) {\n"
	  "	struct timespec ts;\n"
	  "	ts.tv_sec = ts.tv_nsec = 1;\n"
	  "}\n" },
	{ "HAVE_SECTION_START_STOP", "__attribute__((section)) and __start/__stop",
	  "DEFINES_FUNC", NULL, NULL,
	  "static void *__attribute__((__section__(\"mysec\"))) p = &p;\n"
	  "static int func(void) {\n"
	  "	extern void *__start_mysec[], *__stop_mysec[];\n"
	  "	return __stop_mysec - __start_mysec;\n"
	  "}\n" },
	{ "HAVE_STACK_GROWS_UPWARDS", "stack grows upwards",
	  "DEFINES_EVERYTHING|EXECUTE", NULL, NULL,
	  "#include <stddef.h>\n"
	  "static ptrdiff_t nest(const void *base, unsigned int i)\n"
	  "{\n"
	  "	if (i == 0)\n"
	  "		return (const char *)&i - (const char *)base;\n"
	  "	return nest(base, i-1);\n"
	  "}\n"
	  "int main(int argc, char *argv[]) {\n"
	  "	(void)argv;\n"
	  "	return (nest(&argc, argc) > 0) ? 0 : 1;\n"
	  "}\n" },
	{ "HAVE_STATEMENT_EXPR", "statement expression support",
	  "INSIDE_MAIN", NULL, NULL,
	  "return ({ int x = argc; x == argc ? 0 : 1; });" },
	{ "HAVE_SYS_FILIO_H", "<sys/filio.h>",
	  "OUTSIDE_MAIN", NULL, NULL, /* Solaris needs this for FIONREAD */
	  "#include <sys/filio.h>\n" },
	{ "HAVE_SYS_TERMIOS_H", "<sys/termios.h>",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "#include <sys/termios.h>\n" },
	{ "HAVE_SYS_UNISTD_H", "<sys/unistd.h>",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "#include <sys/unistd.h>\n" },
	{ "HAVE_TYPEOF", "__typeof__ support",
	  "INSIDE_MAIN", NULL, NULL,
	  "__typeof__(argc) i; i = argc; return i == argc ? 0 : 1;" },
	{ "HAVE_UNALIGNED_ACCESS", "unaligned access to int",
	  "DEFINES_EVERYTHING|EXECUTE", NULL, NULL,
	  "#include <string.h>\n"
	  "int main(int argc, char *argv[]) {\n"
	  "	(void)argc;\n"
	  "     char pad[sizeof(int *) * 1];\n"
	  "	strncpy(pad, argv[0], sizeof(pad));\n"
	  "	int *x = (int *)pad, *y = (int *)(pad + 1);\n"
	  "	return *x == *y;\n"
	  "}\n" },
	{ "HAVE_UTIME", "utime() declaration",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <utime.h>\n"
	  "static int func(const char *filename) {\n"
	  "	struct utimbuf times = { 0 };\n"
	  "	return utime(filename, &times);\n"
	  "}" },
	{ "HAVE_WARN_UNUSED_RESULT", "__attribute__((warn_unused_result))",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <utime.h>\n"
	  "static __attribute__((warn_unused_result)) int func(int i) {\n"
	  "	return i + 1;\n"
	  "}" },
	{ "HAVE_OPENMP", "#pragma omp and -fopenmp support",
	  "INSIDE_MAIN", NULL, NULL,
	  "int i;\n"
	  "#pragma omp parallel for\n"
	  "for(i = 0; i < 0; i++) {};\n"
	  "return 0;\n",
	  "-Werror -fopenmp" },
	{ "HAVE_VALGRIND_MEMCHECK_H", "<valgrind/memcheck.h>",
	  "OUTSIDE_MAIN", NULL, NULL,
	  "#include <valgrind/memcheck.h>\n" },
	{ "HAVE_UCONTEXT", "working <ucontext.h",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE",
	  NULL, NULL,
	  "#include <ucontext.h>\n"
	  "static int x = 0;\n"
	  "static char stack[2048];\n"
	  "static ucontext_t a, b;\n"
	  "static void fn(void) {\n"
	  "	x |= 2;\n"
	  "	setcontext(&b);\n"
	  "	x |= 4;\n"
	  "}\n"
	  "int main(void) {\n"
	  "	x |= 1;\n"
	  "	getcontext(&a);\n"
	  "	a.uc_stack.ss_sp = stack;\n"
	  "	a.uc_stack.ss_size = sizeof(stack);\n"
	  "	makecontext(&a, fn, 0);\n"
	  "	swapcontext(&b, &a);\n"
	  "	return (x == 3) ? 0 : 1;\n"
	  "}\n"
	},
	{ "HAVE_POINTER_SAFE_MAKECONTEXT", "passing pointers via makecontext()",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE",
	  "HAVE_UCONTEXT", NULL,
	  "#include <stddef.h>\n"
	  "#include <ucontext.h>\n"
	  "static int worked = 0;\n"
	  "static char stack[1024];\n"
	  "static ucontext_t a, b;\n"
	  "static void fn(void *p, void *q) {\n"
	  "	void *cp = &worked;\n"
	  "	void *cq = (void *)(~((ptrdiff_t)cp));\n"
	  "	if ((p == cp) && (q == cq))\n"
	  "		worked = 1;\n"
	  "	setcontext(&b);\n"
	  "}\n"
	  "int main(void) {\n"
	  "	void *ap = &worked;\n"
	  "	void *aq = (void *)(~((ptrdiff_t)ap));\n"
	  "	getcontext(&a);\n"
	  "	a.uc_stack.ss_sp = stack;\n"
	  "	a.uc_stack.ss_size = sizeof(stack);\n"
	  "	makecontext(&a, (void (*)(void))fn, 2, ap, aq);\n"
	  "	swapcontext(&b, &a);\n"
	  "	return worked ? 0 : 1;\n"
	  "}\n"
	},
};

static void c12r_err(int eval, const char *fmt, ...)
{
	int err_errno = errno;
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(err_errno));
	exit(eval);
}

static void c12r_errx(int eval, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}

static void start_test(const char *what, const char *why)
{
	if (like_a_libtool) {
		printf("%s%s... ", what, why);
		fflush(stdout);
	}
}

static void end_test(bool result)
{
	if (like_a_libtool)
		printf("%s\n", result ? "yes" : "no");
}

static size_t fcopy(FILE *fsrc, FILE *fdst)
{
	char buffer[BUFSIZ];
	size_t rsize, wsize;
	size_t copied = 0;

	while ((rsize = fread(buffer, 1, BUFSIZ, fsrc)) > 0) {
		wsize = fwrite(buffer, 1, rsize, fdst);
		copied += wsize;
		if (wsize != rsize)
			break;
	}

	return copied;
}

static char *grab_stream(FILE *file)
{
	size_t max, ret, size = 0;
	char *buffer;

	max = BUFSIZ;
	buffer = malloc(max);
	while ((ret = fread(buffer+size, 1, max - size, file)) == max - size) {
		size += ret;
		buffer = realloc(buffer, max *= 2);
	}
	size += ret;
	if (ferror(file))
		c12r_err(EXIT_TROUBLE_RUNNING, "reading from command");
	buffer[size] = '\0';
	return buffer;
}

static char *run(const char *cmd, int *exitstatus)
{
	static const char redir[] = " 2>&1";
	size_t cmdlen;
	char *cmdredir;
	FILE *cmdout;
	char *ret;

	cmdlen = strlen(cmd);
	cmdredir = malloc(cmdlen + sizeof(redir));
	memcpy(cmdredir, cmd, cmdlen);
	memcpy(cmdredir + cmdlen, redir, sizeof(redir));

	cmdout = popen(cmdredir, "r");
	if (!cmdout)
		c12r_err(EXIT_TROUBLE_RUNNING, "popen \"%s\"", cmdredir);

	free(cmdredir);

	ret = grab_stream(cmdout);
	*exitstatus = pclose(cmdout);
	return ret;
}

static char *connect_args(const char *argv[], const char *outflag,
		const char *files)
{
	unsigned int i;
	char *ret;
	size_t len = strlen(outflag) + strlen(files) + 1;

	for (i = 1; argv[i]; i++)
		len += 1 + strlen(argv[i]);

	ret = malloc(len);
	len = 0;
	for (i = 1; argv[i]; i++) {
		strcpy(ret + len, argv[i]);
		len += strlen(argv[i]);
		if (argv[i+1] || *outflag)
			ret[len++] = ' ';
	}
	strcpy(ret + len, outflag);
	len += strlen(outflag);
	strcpy(ret + len, files);
	return ret;
}

static struct test *find_test(const char *name)
{
	unsigned int i;

	for (i = 0; tests[i].name; i++) {
		if (strcmp(tests[i].name, name) == 0)
			return &tests[i];
	}
	c12r_errx(EXIT_BAD_TEST, "Unknown test %s", name);
	abort();
}

#define PRE_BOILERPLATE "/* Test program generated by configurator. */\n"
#define MAIN_START_BOILERPLATE \
	"int main(int argc, char *argv[]) {\n" \
	"	(void)argc;\n" \
	"	(void)argv;\n"
#define USE_FUNC_BOILERPLATE "(void)func;\n"
#define MAIN_BODY_BOILERPLATE "return 0;\n"
#define MAIN_END_BOILERPLATE "}\n"

static bool run_test(const char *cmd, struct test *test)
{
	char *output, *newcmd;
	FILE *outf;
	int status;

	if (test->done)
		return test->answer;

	if (test->depends) {
		size_t len;
		const char *deps = test->depends;
		char *dep;

		/* Space-separated dependencies, could be ! for inverse. */
		while ((len = strcspn(deps, " ")) != 0) {
			bool positive = true;
			if (deps[len]) {
				dep = strdup(deps);
				dep[len] = '\0';
			} else {
				dep = (char *)deps;
			}

			if (dep[0] == '!') {
				dep++;
				positive = false;
			}
			if (run_test(cmd, find_test(dep)) != positive) {
				test->answer = false;
				test->done = true;
				return test->answer;
			}
			if (deps[len])
				free(dep);

			deps += len;
			deps += strspn(deps, " ");
		}
	}

	outf = fopen(INPUT_FILE, verbose > 1 ? "w+" : "w");
	if (!outf)
		c12r_err(EXIT_TROUBLE_RUNNING, "creating %s", INPUT_FILE);

	fprintf(outf, "%s", PRE_BOILERPLATE);

	if (strstr(test->style, "INSIDE_MAIN")) {
		fprintf(outf, "%s", MAIN_START_BOILERPLATE);
		fprintf(outf, "%s", test->fragment);
		fprintf(outf, "%s", MAIN_END_BOILERPLATE);
	} else if (strstr(test->style, "OUTSIDE_MAIN")) {
		fprintf(outf, "%s", test->fragment);
		fprintf(outf, "%s", MAIN_START_BOILERPLATE);
		fprintf(outf, "%s", MAIN_BODY_BOILERPLATE);
		fprintf(outf, "%s", MAIN_END_BOILERPLATE);
	} else if (strstr(test->style, "DEFINES_FUNC")) {
		fprintf(outf, "%s", test->fragment);
		fprintf(outf, "%s", MAIN_START_BOILERPLATE);
		fprintf(outf, "%s", USE_FUNC_BOILERPLATE);
		fprintf(outf, "%s", MAIN_BODY_BOILERPLATE);
		fprintf(outf, "%s", MAIN_END_BOILERPLATE);
	} else if (strstr(test->style, "DEFINES_EVERYTHING")) {
		fprintf(outf, "%s", test->fragment);
	} else
		c12r_errx(EXIT_BAD_TEST, "Unknown style for test %s: %s",
			  test->name, test->style);

	if (verbose > 1) {
		fseek(outf, 0, SEEK_SET);
		fcopy(outf, stdout);
	}

	fclose(outf);

	newcmd = strdup(cmd);

	if (test->flags) {
		newcmd = realloc(newcmd, strlen(newcmd) + strlen(" ")
				+ strlen(test->flags) + 1);
		strcat(newcmd, " ");
		strcat(newcmd, test->flags);
		if (verbose > 1)
			printf("Extra flags line: %s", newcmd);
	}

	if (test->link) {
		newcmd = realloc(newcmd, strlen(newcmd) + strlen(" ")
				+ strlen(test->link) + 1);
		strcat(newcmd, " ");
		strcat(newcmd, test->link);
		if (verbose > 1)
			printf("Extra link line: %s", newcmd);
	}

	start_test("checking for ", test->desc);
	output = run(newcmd, &status);

	free(newcmd);

	if (status != 0 || strstr(output, "warning")) {
		if (verbose)
			printf("Compile %s for %s, status %i: %s\n",
			       status ? "fail" : "warning",
			       test->name, status, output);
		if (strstr(test->style, "EXECUTE")
		    && !strstr(test->style, "MAY_NOT_COMPILE"))
			c12r_errx(EXIT_BAD_TEST,
				  "Test for %s did not compile:\n%s",
				  test->name, output);
		test->answer = false;
		free(output);
	} else {
		/* Compile succeeded. */
		free(output);
		/* We run INSIDE_MAIN tests for sanity checking. */
		if (strstr(test->style, "EXECUTE")
		    || strstr(test->style, "INSIDE_MAIN")) {
			output = run("." DIR_SEP OUTPUT_FILE, &status);
			if (!strstr(test->style, "EXECUTE") && status != 0)
				c12r_errx(EXIT_BAD_TEST,
					  "Test for %s failed with %i:\n%s",
					  test->name, status, output);
			if (verbose && status)
				printf("%s exited %i\n", test->name, status);
			free(output);
		}
		test->answer = (status == 0);
	}
	test->done = true;
	end_test(test->answer);

	if (test->answer && test->overrides) {
		struct test *override = find_test(test->overrides);
		override->done = true;
		override->answer = true;
	}
	return test->answer;
}

static char *any_field(char **fieldname)
{
	char buf[1000];
	for (;;) {
		char *p, *eq;

		if (!fgets(buf, sizeof(buf), stdin))
			return NULL;

		p = buf;
		/* Ignore whitespace, lines starting with # */
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n')
			continue;

		eq = strchr(p, '=');
		if (!eq)
			c12r_errx(EXIT_BAD_INPUT, "no = in line: %s", p);
		*eq = '\0';
		*fieldname = strdup(p);
		p = eq + 1;
		if (strlen(p) && p[strlen(p)-1] == '\n')
			p[strlen(p)-1] = '\0';
		return strdup(p);
	}
}

static char *read_field(const char *name, bool compulsory)
{
	char *fieldname, *value;

	value = any_field(&fieldname);
	if (!value) {
		if (!compulsory)
			return NULL;
		c12r_errx(EXIT_BAD_INPUT, "Could not read field %s", name);
	}
	if (strcmp(fieldname, name) != 0)
		c12r_errx(EXIT_BAD_INPUT,
			  "Expected field %s not %s", name, fieldname);
	return value;
}

/* Test descriptions from stdin:
 * Lines starting with # or whitespace-only are ignored.
 *
 * First three non-ignored lines must be:
 *  var=<varname>
 *  desc=<description-for-autotools-style>
 *  style=OUTSIDE_MAIN DEFINES_FUNC INSIDE_MAIN DEFINES_EVERYTHING EXECUTE MAY_NOT_COMPILE
 *
 * Followed by optional lines:
 *  depends=<space-separated-testnames, ! to invert>
 *  link=<extra args for link line>
 *  flags=<extra args for compile line>
 *  overrides=<testname-to-force>
 *
 * Finally a code line, either:
 *  code=<oneline> OR
 *  code=
 *  <lines of code>
 *  <end-comment>
 *
 * And <end-comment> looks like this next comment: */
/*END*/
static bool read_test(struct test *test)
{
	char *field, *value;
	char buf[1000];

	memset(test, 0, sizeof(*test));
	test->name = read_field("var", false);
	if (!test->name)
		return false;
	test->desc = read_field("desc", true);
	test->style = read_field("style", true);
	/* Read any optional fields. */
	while ((value = any_field(&field)) != NULL) {
		if (strcmp(field, "depends") == 0)
			test->depends = value;
		else if (strcmp(field, "link") == 0)
			test->link = value;
		else if (strcmp(field, "flags") == 0)
			test->flags = value;
		else if (strcmp(field, "overrides") == 0)
			test->overrides = value;
		else if (strcmp(field, "code") == 0)
			break;
		else
			c12r_errx(EXIT_BAD_INPUT, "Unknown field %s in %s",
				  field, test->name);
	}
	if (!value)
		c12r_errx(EXIT_BAD_INPUT, "Missing code in %s", test->name);

	if (strlen(value) == 0) {
		/* Multiline program, read to END comment */
		while (fgets(buf, sizeof(buf), stdin) != 0) {
			size_t n;
			if (strncmp(buf, "/*END*/", 7) == 0)
				break;
			n = strlen(value);
			value = realloc(value, n + strlen(buf) + 1);
			strcpy(value + n, buf);
			n += strlen(buf);
		}
	}
	test->fragment = value;
	return true;
}

static void read_tests(size_t num_tests)
{
	while (read_test(tests + num_tests)) {
		num_tests++;
		tests = realloc(tests, num_tests * sizeof(tests[0]));
	}
}

int main(int argc, const char *argv[])
{
	char *cmd;
	unsigned int i;
	const char *default_args[]
		= { "", DEFAULT_COMPILER, DEFAULT_FLAGS, NULL };
	const char *outflag = DEFAULT_OUTPUT_EXE_FLAG;
	const char *configurator_cc = NULL;
	const char *orig_cc;
	const char *varfile = NULL;
	const char *headerfile = NULL;
	bool extra_tests = false;
	FILE *outf;

	if (argc > 0)
		progname = argv[0];

	while (argc > 1) {
		if (strcmp(argv[1], "--help") == 0) {
			printf("Usage: configurator [-v] [--var-file=<filename>] [-O<outflag>] [--configurator-cc=<compiler-for-tests>] [--autotools-style] [--extra-tests] [<compiler> <flags>...]\n"
			       "  <compiler> <flags> will have \"<outflag> <outfile> <infile.c>\" appended\n"
			       "Default: %s %s %s\n",
			       DEFAULT_COMPILER, DEFAULT_FLAGS,
			       DEFAULT_OUTPUT_EXE_FLAG);
			exit(0);
		}
		if (strncmp(argv[1], "-O", 2) == 0) {
			argc--;
			argv++;
			outflag = argv[1] + 2;
			if (!*outflag) {
				fprintf(stderr,
					"%s: option requires an argument -- O\n",
					argv[0]);
				exit(EXIT_BAD_USAGE);
			}
		} else if (strcmp(argv[1], "-v") == 0) {
			argc--;
			argv++;
			verbose++;
		} else if (strcmp(argv[1], "-vv") == 0) {
			argc--;
			argv++;
			verbose += 2;
		} else if (strncmp(argv[1], "--configurator-cc=", 18) == 0) {
			configurator_cc = argv[1] + 18;
			argc--;
			argv++;
		} else if (strncmp(argv[1], "--var-file=", 11) == 0) {
			varfile = argv[1] + 11;
			argc--;
			argv++;
		} else if (strcmp(argv[1], "--autotools-style") == 0) {
			like_a_libtool = true;
			argc--;
			argv++;
		} else if (strncmp(argv[1], "--header-file=", 14) == 0) {
			headerfile = argv[1] + 14;
			argc--;
			argv++;
		} else if (strcmp(argv[1], "--extra-tests") == 0) {
			extra_tests = true;
			argc--;
			argv++;
		} else if (strcmp(argv[1], "--") == 0) {
			break;
		} else if (argv[1][0] == '-') {
			c12r_errx(EXIT_BAD_USAGE, "Unknown option %s", argv[1]);
		} else {
			break;
		}
	}

	if (argc == 1)
		argv = default_args;

	/* Copy with NULL entry at end */
	tests = calloc(sizeof(base_tests)/sizeof(base_tests[0]) + 1,
		       sizeof(base_tests[0]));
	memcpy(tests, base_tests, sizeof(base_tests));

	if (extra_tests)
		read_tests(sizeof(base_tests)/sizeof(base_tests[0]));

	orig_cc = argv[1];
	if (configurator_cc)
		argv[1] = configurator_cc;

	cmd = connect_args(argv, outflag, OUTPUT_FILE " " INPUT_FILE);
	if (like_a_libtool) {
		start_test("Making autoconf users comfortable", "");
		sleep(1);
		end_test(1);
	}
	for (i = 0; tests[i].name; i++)
		run_test(cmd, &tests[i]);
	free(cmd);

	remove(OUTPUT_FILE);
	remove(INPUT_FILE);

	if (varfile) {
		FILE *vars;

		if (strcmp(varfile, "-") == 0)
			vars = stdout;
		else {
			start_test("Writing variables to ", varfile);
			vars = fopen(varfile, "a");
			if (!vars)
				c12r_err(EXIT_TROUBLE_RUNNING,
					 "Could not open %s", varfile);
		}
		for (i = 0; tests[i].name; i++)
			fprintf(vars, "%s=%u\n", tests[i].name, tests[i].answer);
		if (vars != stdout) {
			if (fclose(vars) != 0)
				c12r_err(EXIT_TROUBLE_RUNNING,
					 "Closing %s", varfile);
			end_test(1);
		}
	}

	if (headerfile) {
		start_test("Writing header to ", headerfile);
		outf = fopen(headerfile, "w");
		if (!outf)
			c12r_err(EXIT_TROUBLE_RUNNING,
				 "Could not open %s", headerfile);
	} else
		outf = stdout;

	fprintf(outf, "/* Generated by CCAN configurator */\n"
	       "#ifndef CCAN_CONFIG_H\n"
	       "#define CCAN_CONFIG_H\n");
	fprintf(outf, "#ifndef _GNU_SOURCE\n");
	fprintf(outf, "#define _GNU_SOURCE /* Always use GNU extensions. */\n");
	fprintf(outf, "#endif\n");
	fprintf(outf, "#define CCAN_COMPILER \"%s\"\n", orig_cc);
	cmd = connect_args(argv + 1, "", "");
	fprintf(outf, "#define CCAN_CFLAGS \"%s\"\n", cmd);
	free(cmd);
	fprintf(outf, "#define CCAN_OUTPUT_EXE_CFLAG \"%s\"\n\n", outflag);
	/* This one implies "#include <ccan/..." works, eg. for tdb2.h */
	fprintf(outf, "#define HAVE_CCAN 1\n");
	for (i = 0; tests[i].name; i++)
		fprintf(outf, "#define %s %u\n", tests[i].name, tests[i].answer);
	fprintf(outf, "#endif /* CCAN_CONFIG_H */\n");

	if (headerfile) {
		if (fclose(outf) != 0)
			c12r_err(EXIT_TROUBLE_RUNNING, "Closing %s", headerfile);
		end_test(1);
	}

	return 0;
}
