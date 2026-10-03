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
#define DEFAULT_OUTPUT_OBJ_FLAG "-c -Fo:"
#else
#define DEFAULT_COMPILER "cc"
#define DEFAULT_FLAGS "-g3 -ggdb -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition"
#define DEFAULT_OUTPUT_EXE_FLAG "-o"
#define DEFAULT_OUTPUT_OBJ_FLAG "-c -o"
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
static const char *compiler = DEFAULT_COMPILER;
static const char *flags = DEFAULT_FLAGS;
static const char *output_exe_flag = DEFAULT_OUTPUT_EXE_FLAG;
static const char *output_obj_flag = DEFAULT_OUTPUT_OBJ_FLAG;
static const char *wrapper;

struct test {
	const char *name;
	const char *desc;
	/*
	 * Template style flags (pick one):
	 * STATIC_ASSERT:
	 * - fragment is a compile-time constant expression that must be true.
	 * OUTSIDE_MAIN:
	 * - put a simple boilerplate main() below fragment.
	 * DEFINES_FUNC:
	 * - defines a static function called func; adds ref to avoid warnings
	 * INSIDE_MAIN:
	 * - put fragment inside main(); implies EXECUTE.
	 * DEFINES_EVERYTHING:
	 * - don't add any boilerplate at all.
	 *
	 * Execution flags:
	 * EXECUTE:
	 * - a runtime test; must compile, link, run, and exit 0 to pass.
	 * MAY_NOT_COMPILE:
	 * - Only useful with EXECUTE: don't abort if it doesn't compile.
	 * <nothing>:
	 * - a compile test; must compile to pass.
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
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "enum { TEST = 1/(sizeof(off_t) == 4) };\n" },
	{ "HAVE_ALIGNOF", "__alignof__ support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__alignof__(double) > 0" },
	{ "HAVE_ASPRINTF", "asprintf() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <stdio.h>\n"
	  "int (*func)(char **, const char *, ...) = &asprintf;\n" },
	{ "HAVE_ATTRIBUTE_COLD", "__attribute__((cold)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((cold)) func(int);\n" },
	{ "HAVE_ATTRIBUTE_CONST", "__attribute__((const)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((const)) func(int);\n" },
	{ "HAVE_ATTRIBUTE_DEPRECATED", "__attribute__((deprecated)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((deprecated)) func(int);\n" },
	{ "HAVE_ATTRIBUTE_NONNULL", "__attribute__((nonnull)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((nonnull)) func(char *);\n" },
	{ "HAVE_ATTRIBUTE_RETURNS_NONNULL", "__attribute__((returns_nonnull)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "const char * __attribute__((returns_nonnull)) func(void);\n" },
	{ "HAVE_ATTRIBUTE_SENTINEL", "__attribute__((sentinel)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((sentinel)) func(int, ...);\n" },
	{ "HAVE_ATTRIBUTE_PURE", "__attribute__((pure)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((pure)) func(int);\n" },
	{ "HAVE_ATTRIBUTE_MAY_ALIAS", "__attribute__((may_alias)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "typedef short __attribute__((__may_alias__)) short_a;\n" },
	{ "HAVE_ATTRIBUTE_NORETURN", "__attribute__((noreturn)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "void __attribute__((noreturn)) func(void);\n" },
	{ "HAVE_ATTRIBUTE_PRINTF", "__attribute__ format printf support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "void __attribute__((format(__printf__, 1, 2))) func(const char *, ...);\n" },
	{ "HAVE_ATTRIBUTE_UNUSED", "__attribute__((unused)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((unused)) func(int);\n" },
	{ "HAVE_ATTRIBUTE_USED", "__attribute__((used)) support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "int __attribute__((used)) func(int);\n" },
	{ "HAVE_BACKTRACE", "backtrace() in <execinfo.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <execinfo.h>\n"
	  "int (*func)(void **, int) = &backtrace;\n" },
	{ "HAVE_BIG_ENDIAN", "big endian",
	  "DEFINES_EVERYTHING", "!HAVE_LITTLE_ENDIAN", NULL,
	  "#if defined(__BYTE_ORDER__)\n"
	  "	enum { TEST = 1/(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) };\n"
	  "#elif defined(__GLIBC__)\n"
	  "#	include <endian.h>\n"
	  "	enum { TEST = 1/(__BYTE_ORDER == __BIG_ENDIAN) };\n"
	  "#elif !defined(_BIG_ENDIAN) && \\\n"
	  "	!defined(__hppa) && !defined(__hppa__) && \\\n"
	  "	!defined(__mips) && !defined(__mips__) && \\\n"
	  "	!defined(_M_PPC) && !defined(__powerpc__) && !defined(__ppc__) && \\\n"
	  "	!defined(__powerpc64__) && !defined(__ppc64__) && \\\n"
	  "	!defined(__s390__) && !defined(__s390x__) \\\n"
	  "	!defined(__sparc) && !defined(__sparc__)\n"
	  "# error\n"
	  "#endif\n" },
	{ "HAVE_BIG_ENDIAN_RUNTIME", "big endian (runtime test)",
	  "INSIDE_MAIN|EXECUTE", "!HAVE_BIG_ENDIAN !HAVE_LITTLE_ENDIAN", NULL,
	  "union { int i; char c[sizeof(int)]; } u;\n"
	  "u.i = 0x01020304;\n"
	  "return u.c[0] == 0x01 && u.c[1] == 0x02 && u.c[2] == 0x03 && u.c[3] == 0x04 ? 0 : 1;",
	  NULL, "HAVE_BIG_ENDIAN" },
	{ "HAVE_BSWAP_64", "bswap_64() in <byteswap.h>",
	  "DEFINES_FUNC", "HAVE_BYTESWAP_H", NULL,
	  "#include <byteswap.h>\n"
	  "static int func(int x) { return bswap_64(x); }\n" },
	{ "HAVE_BUILTIN_CHOOSE_EXPR", "__builtin_choose_expr support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_choose_expr(1, 0, \"garbage\") == 0" },
	{ "HAVE_BUILTIN_CLZ", "__builtin_clz support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_clz(1U)" },
	{ "HAVE_BUILTIN_CLZL", "__builtin_clzl support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_clzl(1UL)" },
	{ "HAVE_BUILTIN_CLZLL", "__builtin_clzll support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_clzll(1ULL)" },
	{ "HAVE_BUILTIN_CTZ", "__builtin_ctz support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ctz(1U)" },
	{ "HAVE_BUILTIN_CTZL", "__builtin_ctzl support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ctzl(1UL)" },
	{ "HAVE_BUILTIN_CTZLL", "__builtin_ctzll support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ctzll(1ULL)" },
	{ "HAVE_BUILTIN_CONSTANT_P", "__builtin_constant_p support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_constant_p(1)" },
	{ "HAVE_BUILTIN_EXPECT", "__builtin_expect support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_expect(sizeof(char) == 1, 1)" },
	{ "HAVE_BUILTIN_FFS", "__builtin_ffs support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ffs(0)" },
	{ "HAVE_BUILTIN_FFSL", "__builtin_ffsl support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ffsl(0L)" },
	{ "HAVE_BUILTIN_FFSLL", "__builtin_ffsll support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_ffsll(0LL)" },
	{ "HAVE_BUILTIN_POPCOUNT", "__builtin_popcount support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_popcount(255U) == 8" },
	{ "HAVE_BUILTIN_POPCOUNTL",  "__builtin_popcountl support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_popcountl(255UL) == 8" },
	{ "HAVE_BUILTIN_POPCOUNTLL", "__builtin_popcountll support",
	  "STATIC_ASSERT", NULL, NULL,
	  "__builtin_popcountll(255ULL) == 8" },
	{ "HAVE_BUILTIN_TYPES_COMPATIBLE_P", "__builtin_types_compatible_p support",
	  "STATIC_ASSERT", NULL, NULL,
	  "!__builtin_types_compatible_p(char *, int)" },
	{ "HAVE_ICCARM_INTRINSICS", "<intrinsics.h>",
	  "DEFINES_FUNC", NULL, NULL,
	  "#include <intrinsics.h>\n"
	  "static int func(int v) {\n"
	  "	return __CLZ(__RBIT(v));\n"
	  "}\n" },
	{ "HAVE_BYTESWAP_H", "<byteswap.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <byteswap.h>\n" },
	{ "HAVE_CLOCK_GETTIME", "clock_gettime() declaration",
	  "DEFINES_EVERYTHING", "HAVE_STRUCT_TIMESPEC", NULL,
	  "#include <time.h>\n"
	  "int (*func)(clockid_t, struct timespec *) = &clock_gettime;\n" },
	{ "HAVE_CLOCK_GETTIME_IN_LIBRT", "clock_gettime() in librt",
	  "DEFINES_EVERYTHING",
	  "HAVE_STRUCT_TIMESPEC !HAVE_CLOCK_GETTIME",
	  "-lrt",
	  "#include <time.h>\n"
	  "int (*func)(clockid_t, struct timespec *) = &clock_gettime;\n",
	  /* This means HAVE_CLOCK_GETTIME, too */
	  NULL, "HAVE_CLOCK_GETTIME" },
	{ "HAVE_COMPOUND_LITERALS", "compound literal support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "const int *foo = (int[]) { 1, 2, 3, 4 };\n" },
	{ "HAVE_FCHDIR", "fchdir() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <unistd.h>\n"
	  "int (*func)(int) = &fchdir;\n" },
	{ "HAVE_ERR_H", "<err.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <err.h>\n"
	  "void (*func0)(int, const char *, ...) = &err;\n"
	  "void (*func1)(int, const char *, ...) = &errx;\n"
	  "void (*func2)(const char *, ...) = &warn;\n"
	  "void (*func3)(const char *, ...) = &warnx;\n" },
	{ "HAVE_FILE_OFFSET_BITS", "_FILE_OFFSET_BITS to get 64-bit offsets",
	  "DEFINES_EVERYTHING", "HAVE_32BIT_OFF_T", NULL,
	  "#define _FILE_OFFSET_BITS 64\n"
	  "#include <sys/types.h>\n"
	  "enum { TEST = 1/(sizeof(off_t) == 8) };\n" },
	{ "HAVE_FOR_LOOP_DECLARATION", "for loop declaration support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static void func(void) { for (int i = 0; i < 1; ++i); }\n" },
	{ "HAVE_FLEXIBLE_ARRAY_MEMBER", "flexible array member support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "struct foo { unsigned int x; int arr[]; };" },
	{ "HAVE_GETPAGESIZE", "getpagesize() in <unistd.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <unistd.h>\n"
	  "int (*func)(void) = &getpagesize;\n" },
	{ "HAVE_ISBLANK", "isblank() in <ctype.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <ctype.h>\n"
	  "int (*func)(int) = &isblank;\n" },
	{ "HAVE_LITTLE_ENDIAN", "little endian",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#if defined(__BYTE_ORDER__)\n"
	  "	enum { TEST = 1/(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) };\n"
	  "#elif defined(__GLIBC__)\n"
	  "#	include <endian.h>\n"
	  "	enum { TEST = 1/(__BYTE_ORDER == __LITTLE_ENDIAN) };\n"
	  "#elif !defined(_LITTLE_ENDIAN) && \\\n"
	  "	!defined(_M_ALPHA) && !defined(__alpha) && !defined(__alpha__) && \\\n"
	  "	!defined(_M_AMD64) && !defined(__amd64) && !defined(__amd64__) && \\\n"
	  "	!defined(_M_ARM) && !defined(__arm) && !defined(__arm__) && \\\n"
	  "	!defined(_M_ARM64) && !defined(__aarch64) && !defined(__aarch64__) && \\\n"
	  "	!defined(_M_IA64) && !defined(__ia64) && !defined(__ia64__) && \\\n"
	  "	!defined(_M_IX86) && !defined(__i386) && !defined(__i386__) && \\\n"
	  "	!defined(_M_X64) && !defined(__x86_64) && !defined(__x86_64__) && \\\n"
	  "	!defined(__bfin) && !defined(__bfin__)\n"
	  "# error\n"
	  "#endif\n" },
	{ "HAVE_LITTLE_ENDIAN_RUNTIME", "little endian (runtime test)",
	  "INSIDE_MAIN|EXECUTE", "!HAVE_BIG_ENDIAN !HAVE_LITTLE_ENDIAN", NULL,
	  "union { int i; char c[sizeof(int)]; } u;\n"
	  "u.i = 0x01020304;\n"
	  "return u.c[0] == 0x04 && u.c[1] == 0x03 && u.c[2] == 0x02 && u.c[3] == 0x01 ? 0 : 1;",
	  NULL, "HAVE_LITTLE_ENDIAN" },
	{ "HAVE_MEMMEM", "memmem() in <string.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <string.h>\n"
	  "void * (*func)(const void *, size_t, const void *, size_t) = &memmem;\n" },
	{ "HAVE_MEMRCHR", "memrchr() in <string.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <string.h>\n"
	  "void * (*func)(const void *, int, size_t) = &memrchr;\n" },
	{ "HAVE_MMAP", "mmap() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/mman.h>\n"
	  "void * (*func)(void *, size_t, int, int, int, off_t) = &mmap;\n" },
	{ "HAVE_QSORT_R_PRIVATE_LAST", "qsort_r cmp takes trailing arg",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <stdlib.h>\n"
	  "void (*func)(void *, size_t, size_t, int (*)(const void *, const void *, void *), void *) = &qsort_r;\n" },
	{ "HAVE_STRUCT_TIMESPEC", "struct timespec declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <time.h>\n"
	  "const struct timespec ts = { .tv_sec = 1, .tv_nsec = 1 };\n" },
	{ "HAVE_SECTION_START_STOP", "__attribute__((section)) and __start/__stop",
	  "DEFINES_FUNC", NULL, NULL,
	  "static void *__attribute__((__section__(\"mysec\"))) p = &p;\n"
	  "static int func(void) {\n"
	  "	extern void *__start_mysec[], *__stop_mysec[];\n"
	  "	return __stop_mysec - __start_mysec;\n"
	  "}\n" },
	{ "HAVE_STACK_GROWS_UPWARDS", "stack grows upwards",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#if !defined(__hppa)\n"
	  "# error\n"
	  "#endif\n" },
	{ "HAVE_STATEMENT_EXPR", "statement expression support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static int func(void) { return ({ int x = 0; x == 0 ? 0 : 1; }); }\n" },
	{ "HAVE_STATIC_ASSERT", "_Static_assert support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "_Static_assert(1, \"OK\");\n" },
	{ "HAVE_SYS_FILIO_H", "<sys/filio.h>",
	  "DEFINES_EVERYTHING", NULL, NULL, /* Solaris needs this for FIONREAD */
	  "#include <sys/filio.h>\n" },
	{ "HAVE_SYS_TERMIOS_H", "<sys/termios.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/termios.h>\n" },
	{ "HAVE_SYS_UNISTD_H", "<sys/unistd.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/unistd.h>\n" },
	{ "HAVE_TYPEOF", "__typeof__ support",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "static int i;\n"
	  "__typeof__(i) *p = &i;\n" },
	{ "HAVE_EFFICIENT_UNALIGNED_ACCESS", "efficient unaligned memory access",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#if !defined(_M_AMD64) && !defined(__amd64) && !defined(__amd64__) && \\\n"
	  "	!defined(__ARM_FEATURE_UNALIGNED) && \\\n"
	  "	!defined(_M_ARM64) && !defined(__aarch64) && !defined(__aarch64__) && \\\n"
	  "	!defined(_M_IX86) && !defined(__i386) && !defined(__i386__) && \\\n"
	  "	!defined(_M_PPC) && !defined(__powerpc__) && !defined(__ppc__) && \\\n"
	  "	!defined(__powerpc64__) && !defined(__ppc64__) && \\\n"
	  "	!defined(__s390__) && !defined(__s390x__) \\\n"
	  "	!defined(_M_X64) && !defined(__x86_64) && !defined(__x86_64__)\n"
	  "# error\n"
	  "#endif\n",
	  NULL, "HAVE_UNALIGNED_ACCESS" },
	{ "HAVE_NO_UNALIGNED_ACCESS", "known lack of unaligned memory access",
	  "DEFINES_EVERYTHING", "!HAVE_EFFICIENT_UNALIGNED_ACCESS", NULL,
	  "#if !defined(_M_ALPHA) && !defined(__alpha) && !defined(__alpha__) && \\\n"
	  "	(!defined(_M_ARM) && !defined(__arm) && !defined(__arm__) || defined(__ARM_FEATURE_UNALIGNED)) && \\\n"
	  "	!defined(__hppa) && !defined(__hppa__) && \\\n"
	  "	!defined(__mips) && !defined(__mips__) && \\\n"
	  "	!defined(__sparc) && !defined(__sparc__)\n"
	  "# error\n"
	  "#endif\n" },
	{ "HAVE_UNALIGNED_ACCESS", "unaligned memory access (runtime test)",
	  "DEFINES_EVERYTHING|EXECUTE", "!HAVE_NO_UNALIGNED_ACCESS", NULL,
	  "#include <string.h>\n"
	  "int main(int argc, char *argv[]) {\n"
	  "	(void)argc;\n"
	  "     char pad[sizeof(int) + 1];\n"
	  "	memcpy(pad, argv[0], sizeof(pad));\n"
	  "	int *x = (int *)pad, *y = (int *)(pad + 1);\n"
	  "	return *x == *y;\n"
	  "}\n" },
	{ "HAVE_UTIME", "utime() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <utime.h>\n"
	  "int (*func)(const char *, const struct utimbuf *) = &utime;\n" },
	{ "HAVE_WARN_UNUSED_RESULT", "__attribute__((warn_unused_result))",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/types.h>\n"
	  "#include <utime.h>\n"
	  "__attribute__((warn_unused_result)) int func(void);\n" },
	{ "HAVE_OPENMP", "#pragma omp and -fopenmp support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static void func(void) {\n"
	  "	int i;\n"
	  "#pragma omp parallel for\n"
	  "	for(i = 0; i < 0; ++i);\n"
	  "}\n",
	  "-Werror -fopenmp" },
	{ "HAVE_VALGRIND_MEMCHECK_H", "<valgrind/memcheck.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <valgrind/memcheck.h>\n" },
	{ "HAVE_UCONTEXT", "<ucontext.h>",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <ucontext.h>\n"
	  "int (*func0)(ucontext_t *) = &getcontext;\n"
	  "int (*func1)(const ucontext_t *) = &setcontext;\n"
	  "void (*func2)(ucontext_t *, void (*)(void), int, ...) = &makecontext;\n"
	  "int (*func3)(ucontext_t *, const ucontext_t *) = &swapcontext;\n" },
	{ "HAVE_POINTER_SAFE_MAKECONTEXT", "passing pointers via makecontext()",
	  "DEFINES_EVERYTHING|EXECUTE|MAY_NOT_COMPILE",
	  "HAVE_UCONTEXT", NULL,
	  "#include <stddef.h>\n"
	  "#include <ucontext.h>\n"
	  "static int worked = 0;\n"
	  "static char stack[8192];\n"
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
	{ "HAVE_BUILTIN_CPU_SUPPORTS", "__builtin_cpu_supports support",
	  "DEFINES_FUNC", NULL, NULL,
	  "static int func(void) { return __builtin_cpu_supports(\"mmx\"); }\n" },
	{ "HAVE_CLOSEFROM", "closefrom() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <stdlib.h>\n"
	  "#include <unistd.h>\n"
	  "void (*func)(int) = &closefrom;\n" },
	{ "HAVE_F_CLOSEM", "F_CLOSEM",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <fcntl.h>\n"
	  "#include <unistd.h>\n"
	  "enum { TEST = F_CLOSEM };\n" },
	{ "HAVE_CLOSE_RANGE", "close_range() declaration",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#ifndef _GNU_SOURCE\n"
	  "#define _GNU_SOURCE\n"
	  "#endif\n"
	  "#include <unistd.h>\n"
	  "int (*func)(unsigned, unsigned, int) = &close_range;\n" },
	{ "HAVE_NR_CLOSE_RANGE", "__NR_close_range",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <sys/syscall.h>\n"
	  "#include <unistd.h>\n"
	  "enum { TEST = __NR_close_range };\n" },
	{ "HAVE_F_MAXFD", "F_MAXFD",
	  "DEFINES_EVERYTHING", NULL, NULL,
	  "#include <fcntl.h>\n"
	  "#include <unistd.h>\n"
	  "int test = F_MAXFD;\n" },
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
	fputc('\n', stderr);
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
		puts(result ? "yes" : "no");
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

/*
 * Efficiently joins together an arbitrary number of strings using a glue char.
 * The returned string must be freed when it is no longer needed.
 * Each variadic argument is a pointer to an array of pointers to strings.
 * The last element in each array must be NULL.
 * The last argument must be NULL.
 */
static char *concat(int glue, /* (const char *const *) */...)
{
	va_list ap;
	size_t len = 0;
	const char *const *arg;
	const char *s;
	char *ret, *p;

	va_start(ap, glue);
	while ((arg = va_arg(ap, const char *const *))) {
		while ((s = *arg++)) {
			size_t n = strlen(s);
			len += n + !!n;
		}
	}
	va_end(ap);
	if (!len)
		return strdup("");

	p = ret = malloc(len);
	va_start(ap, glue);
	while ((arg = va_arg(ap, const char *const *))) {
		while ((s = *arg++)) {
			p = stpcpy(p, s);
			*p++ = (char) glue;
		}
	}
	va_end(ap);
	*--p = '\0';

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
#define STATIC_ASSERT_START_BOILERPLATE "enum { TEST = 1/!!("
#define STATIC_ASSERT_END_BOILERPLATE ") };\n"
#define MAIN_START_BOILERPLATE \
	"int main(int argc, char *argv[]) {\n" \
	"	(void)argc;\n" \
	"	(void)argv;\n"
#define USE_FUNC_BOILERPLATE "(void)func;\n"
#define MAIN_BODY_BOILERPLATE "return 0;\n"
#define MAIN_END_BOILERPLATE "}\n"

static bool run_test(struct test *test)
{
	char *output, *newcmd;
	FILE *outf;
	const char *args[4], **arg = args;
	int status;

	if (test->done)
		return test->answer;

	if (test->depends) {
		size_t len;
		const char *deps = test->depends;
		const char *dep;

		/* Space-separated dependencies, could be ! for inverse. */
		while ((len = strcspn(deps += strspn(deps, " "), " ")) != 0) {
			bool positive = deps[0] != '!';
			if (!positive)
				++deps, --len;
			dep = deps[len] ? strndup(deps, len) : deps;
			if (run_test(find_test(dep)) != positive) {
				test->answer = false;
				test->done = true;
				return test->answer;
			}
			if (deps[len])
				free((void *) dep);
			deps += len;
		}
	}

	bool need_run = strstr(test->style, "EXECUTE");

	outf = fopen(INPUT_FILE, verbose > 1 ? "w+" : "w");
	if (!outf)
		c12r_err(EXIT_TROUBLE_RUNNING, "creating %s", INPUT_FILE);

	fputs(PRE_BOILERPLATE, outf);

	if (strstr(test->style, "STATIC_ASSERT")) {
		fputs(STATIC_ASSERT_START_BOILERPLATE, outf);
		fputs(test->fragment, outf);
		fputs(STATIC_ASSERT_END_BOILERPLATE, outf);
	} else if (strstr(test->style, "INSIDE_MAIN")) {
		fputs(MAIN_START_BOILERPLATE, outf);
		fputs(test->fragment, outf);
		fputs(MAIN_END_BOILERPLATE, outf);
		/* We run INSIDE_MAIN tests for sanity checking. */
		need_run = true;
	} else if (strstr(test->style, "OUTSIDE_MAIN")) {
		fputs(test->fragment, outf);
		fputs(MAIN_START_BOILERPLATE, outf);
		fputs(MAIN_BODY_BOILERPLATE, outf);
		fputs(MAIN_END_BOILERPLATE, outf);
	} else if (strstr(test->style, "DEFINES_FUNC")) {
		fputs(test->fragment, outf);
		fputs(MAIN_START_BOILERPLATE, outf);
		fputs(USE_FUNC_BOILERPLATE, outf);
		fputs(MAIN_BODY_BOILERPLATE, outf);
		fputs(MAIN_END_BOILERPLATE, outf);
	} else if (strstr(test->style, "DEFINES_EVERYTHING")) {
		fputs(test->fragment, outf);
	} else
		c12r_errx(EXIT_BAD_TEST, "Unknown style for test %s: %s",
			  test->name, test->style);

	if (verbose > 1) {
		fseek(outf, 0, SEEK_SET);
		fcopy(outf, stdout);
	}

	fclose(outf);

	if (test->flags) {
		*arg++ = test->flags;
		if (verbose > 1)
			printf("Extra compiler flags: %s\n", test->flags);
	}

	if (test->link) {
		*arg++ = test->link;
		if (verbose > 1)
			printf("Extra linker flags: %s\n", test->link);
		*arg++ = output_exe_flag;
	} else if (need_run) {
		*arg++ = output_exe_flag;
	} else {
		*arg++ = output_obj_flag;
	}

	*arg = NULL;
	newcmd = concat(' ', (const char *[]) { compiler, flags, NULL }, args,
			(const char *[]) { OUTPUT_FILE, INPUT_FILE, NULL },
			NULL);

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
		if (need_run) {
			if (wrapper) {
				char *runcmd = malloc(strlen(wrapper) +
					strlen(" ." DIR_SEP OUTPUT_FILE) + 1);
				strcpy(stpcpy(runcmd, wrapper),
				       " ." DIR_SEP OUTPUT_FILE);
				output = run(runcmd, &status);
				free(runcmd);
			} else {
				output = run("." DIR_SEP OUTPUT_FILE, &status);
			}
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
 *  style=STATIC_ASSERT OUTSIDE_MAIN DEFINES_FUNC INSIDE_MAIN DEFINES_EVERYTHING EXECUTE MAY_NOT_COMPILE
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
		tests = realloc(tests, (num_tests + 1) * sizeof(tests[0]));
		tests[num_tests].name = NULL;
	}
}

int main(int argc, const char *argv[])
{
	unsigned int i;
	const char *configurator_cc = NULL;
	const char *orig_cc;
	const char *varfile = NULL;
	const char *headerfile = NULL;
	bool extra_tests = false;
	FILE *outf;

	if (argc > 0)
		progname = *argv++, --argc;

	for (; argc > 0; ++argv, --argc) {
		if (strcmp(argv[0], "--help") == 0) {
			printf("Usage: configurator [-v] [--var-file=<filename>] [--output-exe=<outflag>] [--output-obj=<outflag>] [--configurator-cc=<compiler-for-tests>] [--wrapper=<wrapper-for-tests>] [--autotools-style] [--extra-tests] [<compiler> <flags>...]\n"
			       "  <compiler> <flags> will have \"<outflag> <outfile> <infile.c>\" appended\n"
			       "Default <compiler> <flags>: %s %s\n"
			       "Default --output-exe=\"%s\"\n"
			       "Default --output-obj=\"%s\"\n",
			       DEFAULT_COMPILER, DEFAULT_FLAGS,
			       DEFAULT_OUTPUT_EXE_FLAG,
			       DEFAULT_OUTPUT_OBJ_FLAG);
			exit(0);
		}
		if (strncmp(argv[0], "-O", 2) == 0) { /* legacy compatibility */
			if (!argv[0][2]) {
				fprintf(stderr,
					"%s: option requires an argument -- O\n",
					argv[0]);
				exit(EXIT_BAD_USAGE);
			}
			output_exe_flag = argv[0] + 2;
		} else if (strcmp(argv[0], "-v") == 0) {
			verbose++;
		} else if (strcmp(argv[0], "-vv") == 0) {
			verbose += 2;
		} else if (strncmp(argv[0], "--output-exe=", 13) == 0) {
			output_exe_flag = argv[0] + 13;
		} else if (strncmp(argv[0], "--output-obj=", 13) == 0) {
			output_obj_flag = argv[0] + 13;
		} else if (strncmp(argv[0], "--configurator-cc=", 18) == 0) {
			configurator_cc = argv[0] + 18;
		} else if (strncmp(argv[0], "--wrapper=", 10) == 0) {
			wrapper = argv[0] + 10;
		} else if (strncmp(argv[0], "--var-file=", 11) == 0) {
			varfile = argv[0] + 11;
		} else if (strcmp(argv[0], "--autotools-style") == 0) {
			like_a_libtool = true;
		} else if (strncmp(argv[0], "--header-file=", 14) == 0) {
			headerfile = argv[0] + 14;
		} else if (strcmp(argv[0], "--extra-tests") == 0) {
			extra_tests = true;
		} else if (strcmp(argv[0], "--") == 0) {
			break;
		} else if (argv[0][0] == '-') {
			c12r_errx(EXIT_BAD_USAGE, "Unknown option %s", argv[0]);
		} else {
			break;
		}
	}

	if (argc > 0)
		compiler = *argv++, --argc;
	if (argc > 0)
		flags = concat(' ', argv, NULL);

	/* Copy with NULL entry at end */
	tests = calloc(sizeof(base_tests)/sizeof(base_tests[0]) + 1,
		       sizeof(base_tests[0]));
	memcpy(tests, base_tests, sizeof(base_tests));

	if (extra_tests)
		read_tests(sizeof(base_tests)/sizeof(base_tests[0]));

	orig_cc = compiler;
	if (configurator_cc)
		compiler = configurator_cc;

	if (like_a_libtool) {
		start_test("Making autoconf users comfortable", "");
		sleep(1);
		end_test(1);
	}
	for (i = 0; tests[i].name; i++)
		run_test(&tests[i]);

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

	fputs("/* Generated by CCAN configurator */\n"
	      "#ifndef CCAN_CONFIG_H\n"
	      "#define CCAN_CONFIG_H\n"
	      "#ifndef _GNU_SOURCE\n"
	      "#define _GNU_SOURCE /* Always use GNU extensions. */\n"
	      "#endif\n", outf);
	fprintf(outf, "#define CCAN_COMPILER \"%s\"\n", orig_cc);
	fprintf(outf, "#define CCAN_CFLAGS \"%s\"\n", flags);
	fprintf(outf, "#define CCAN_OUTPUT_EXE_CFLAG \"%s\"\n\n", output_exe_flag);
	fprintf(outf, "#define CCAN_OUTPUT_OBJ_CFLAG \"%s\"\n\n", output_obj_flag);
	/* This one implies "#include <ccan/..." works, eg. for tdb2.h */
	fputs("#define HAVE_CCAN 1\n", outf);
	for (i = 0; tests[i].name; i++)
		fprintf(outf, "#define %s %u\n", tests[i].name, tests[i].answer);
	fputs("#endif /* CCAN_CONFIG_H */\n", outf);

	if (headerfile) {
		if (fclose(outf) != 0)
			c12r_err(EXIT_TROUBLE_RUNNING, "Closing %s", headerfile);
		end_test(1);
	}

	return 0;
}
