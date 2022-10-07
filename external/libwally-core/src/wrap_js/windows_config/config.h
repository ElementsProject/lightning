#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H
#include <stddef.h>

#define HAVE_ATTRIBUTE_WEAK 1
#define HAVE_BIG_ENDIAN 0
#define HAVE_BSWAP_64 0
#define HAVE_BYTESWAP_H 0
#define HAVE_DLFCN_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_LITTLE_ENDIAN 1
#define HAVE_MEMORY_H 1
#define HAVE_MMAP 1
#define HAVE_PTHREAD 1
#define HAVE_PTHREAD_PRIO_INHERIT 1
#define HAVE_PYTHON "2.7"
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1
#define VERSION "0.6"
#if (!defined(_SSIZE_T_DECLARED)) && (!defined(_ssize_t)) && (!defined(ssize_t))
#define ssize_t long long
#endif

#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)

void wally_clear(void *p, size_t len);

#define CCAN_CLEAR_MEMORY(p, len) wally_clear(p, len)

#endif /*LIBWALLYCORE_CONFIG_H*/
