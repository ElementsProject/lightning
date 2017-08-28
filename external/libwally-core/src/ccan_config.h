/* Config directives for ccan */

#ifdef WORDS_BIGENDIAN
# define HAVE_BIG_ENDIAN 1
#else
# define HAVE_LITTLE_ENDIAN 1
#endif

#ifdef __GNUC__
# define HAVE_ATTRIBUTE_COLD 1
# define HAVE_ATTRIBUTE_NORETURN 1
# define HAVE_ATTRIBUTE_PRINTF 1
# define HAVE_ATTRIBUTE_CONST 1
# define HAVE_ATTRIBUTE_PURE 1
# define HAVE_ATTRIBUTE_UNUSED 1
# define HAVE_ATTRIBUTE_USED 1
# define HAVE_BUILTIN_CONSTANT_P 1
# define HAVE_WARN_UNUSED_RESULT 1
#endif

#ifdef HAVE_BYTESWAP_H
#define HAVE_BSWAP_64 1
#endif

#if HAVE_UNALIGNED_ACCESS
#define alignment_ok(p, n) true
#else
#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)
#endif

/* Clear a set of memory areas passed as ptr1, len1, ptr2, len2 etc */
void clear_n(unsigned int count, ...);

#define CCAN_CLEAR_MEMORY(p, len) clear_n(1, p, len)
