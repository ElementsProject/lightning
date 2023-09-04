#ifndef LIGHTNING_COMMON_UTILS_H
#define LIGHTNING_COMMON_UTILS_H
#include "config.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

extern secp256k1_context *secp256k1_ctx;

extern const struct chainparams *chainparams;

/* Unsigned min/max macros: BUILD_ASSERT make sure types are unsigned */
#if HAVE_TYPEOF
#define MUST_BE_UNSIGNED_INT(x) BUILD_ASSERT_OR_ZERO((typeof(x))(-1)>=0)
#else
#define MUST_BE_UNSIGNED_INT(x) 0
#endif

#define min_unsigned(a, b)						\
	(MUST_BE_UNSIGNED_INT(a) + MUST_BE_UNSIGNED_INT(b) + min_u64((a), (b)))

#define max_unsigned(a, b)				\
	(MUST_BE_UNSIGNED_INT(a) + MUST_BE_UNSIGNED_INT(b) + max_u64((a), (b)))

static inline u64 min_u64(u64 a, u64 b)
{
	return a < b ? a : b;
}

static inline u64 max_u64(u64 a, u64 b)
{
	return a < b ? b : a;
}

/* Marker which indicates an (tal) pointer argument is stolen
 * (i.e. eventually freed) by the function.  Unlike TAKEN, which
 * indicates it's only stolen if caller says take() */
#define STEALS

/* Simple accessor function for our own dependencies to use, in order to avoid
 * circular dependencies (should only be used in `bitcoin/y`). */
bool is_elements(const struct chainparams *chainparams);

/* Allocate and fill in a hex-encoded string of this data. */
char *tal_hexstr(const tal_t *ctx, const void *data, size_t len);

/* Allocate and fill a hex-encoding of this tal pointer. */
char *tal_hex(const tal_t *ctx, const tal_t *data);

/* Allocate and fill a buffer with the data of this hex string. */
u8 *tal_hexdata(const tal_t *ctx, const void *str, size_t len);

/* Note: p is never a complex expression, otherwise this multi-evaluates! */
#define tal_arr_expand(p, s)						\
	do {								\
		size_t n_ = tal_count(*(p));				\
		tal_resize((p), n_+1);					\
		(*(p))[n_] = (s);					\
	} while(0)

/**
 * Remove an element from an array
 *
 * This will shift the elements past the removed element, changing
 * their position in memory, so only use this for simple arrays.
 */
#define tal_arr_remove(p, n) tal_arr_remove_((p), sizeof(**p), (n))
void tal_arr_remove_(void *p, size_t elemsize, size_t n);

/**
 * Insert an element in an array
 */
#define tal_arr_insert(p, n, v) \
	do {								\
		size_t n_ = tal_count(*(p));				\
		tal_resize((p), n_+1);					\
		memmove(*(p) + n + 1, *(p) + n, (n_ - n) * sizeof(**(p))); \
		(*(p))[n] = (v);					\
	} while(0)

/* Check for valid UTF-8 */
bool utf8_check(const void *buf, size_t buflen);

/* Check it's UTF-8, return copy (or same if TAKES), or NULL if not valid. */
char *utf8_str(const tal_t *ctx, const u8 *buf TAKES, size_t buflen);

/* Strdup, or pass through NULL */
char *tal_strdup_or_null(const tal_t *ctx, const char *str);

/* Use the POSIX C locale. */
void setup_locale(void);

/* Global temporary convenience context: children freed in io loop core. */
extern const tal_t *tmpctx;

/* Initial creation of tmpctx. */
void setup_tmpctx(void);

/* Free any children of tmpctx. */
void clean_tmpctx(void);

/* Call this before any libwally function which allocates. */
void tal_wally_start(void);

/* Then call this to reparent everything onto this parent */
void tal_wally_end(const tal_t *parent);

/* ... or this if you want to reparent onto something which is
 * allocated by libwally here.  Fixes up this from_wally obj to have a
 * proper tal_name, too! */
#define tal_wally_end_onto(parent, from_wally, type)                           \
	tal_wally_end_onto_(                                                   \
	    (parent), (from_wally),                                            \
	    &stringify(type)[0 * sizeof((from_wally) == (type *)0)])
void tal_wally_end_onto_(const tal_t *parent,
			 tal_t *from_wally,
			 const char *from_wally_name);

/* Define sha256_eq. */
STRUCTEQ_DEF(sha256, 0, u);

/* Define ripemd160_eq. */
STRUCTEQ_DEF(ripemd160, 0, u);

/* If gcc complains about 'may be uninitialized' even at -O3, and the code is
 * clear, use this to suppress it.  Argument should be gcc version it
 * complained on, so we can re-test as gcc evolves. */
#define COMPILER_WANTS_INIT(compiler_versions) = 0

/* For case where we want one thing if DEVELOPER, another if not, particularly
 * for function parameters.
 *
 * Usefully, you can refer to DEVELOPER-only fields here. */
#if DEVELOPER
/* Make sure that nondev is evaluated, and valid */
#define IFDEV(dev, nondev) ((void)(nondev), (dev))
#else
#define IFDEV(dev, nondev) (nondev)
#endif

/* Context which all wally allocations use (see common/setup.c) */
extern const tal_t *wally_tal_ctx;

/* Like mkstemp but resolves template relative to $TMPDIR (or /tmp if unset).
 * Returns created temporary path name at *created if successful. */
int tmpdir_mkstemp(const tal_t *ctx, const char *template TAKES, char **created);

/**
 * tal_strlowering - return the same string by in lower case.
 * @ctx: the context to tal from (often NULL)
 * @string: the string that is going to be lowered (can be take())
 *
 * FIXME: move this in ccan
 */
char *str_lowering(const void *ctx, const char *string TAKES);

/**
 * str_expand: substitute variable references in string via callback function.
 * @ctx: the tal context from which to allocate the returned string.
 * @str: the string containing variable references as described below.
 * @subst: a callback function to resolve variable names to values.
 * @ptr: an opaque pointer to be passed as the first parameter to @subst.
 *
 * Variable references in @str are of the same form used by the POSIX shell,
 * a dollar sign followed by exactly one of the following:
 *  - a brace-enclosed word,
 *  - an ASCII decimal number of any non-zero length,
 *  - a word not beginning with a digit.
 * Here, a "word" means any non-empty run of word characters, which are
 * underscores or characters for which isalnum() returns true.
 *
 * A partial match of one of the above productions is not an error and does not
 * produce a substitution; the characters are simply copied verbatim.
 *
 * For each variable reference encountered in @str, the @subst callback
 * function is invoked, passing @ptr, a pointer to the name of the variable
 * being referenced, and the length of the variable name. The function must
 * return a pointer to a string containing the value to be substituted or NULL.
 * If the pointer is returned as take(), then this function will tal_free() it.
 * If the pointer returned is NULL, then the empty string will be substituted.
 *
 * Within the context of one invocation of str_expand(), the @subst callback
 * function must be invariant with respect to the length of the string that it
 * returns for each distinct given variable name.
 *
 * Returns a copy of @str with all substitutions made.
 *
 * Example:
 * const char *str = "How about a ${adj} ${game of $game?";
 * If subst is a function that returns "nice" when passed "adj" and "chess"
 * when passed "game", then str_expand(NULL, str, subst, NULL) will return
 * "How about a nice ${game of chess?"
 */
char *str_expand(const void *ctx,
                 const char *str TAKES,
                 const char *TAKES (*subst)(const void *ptr,
                                            const char *name,
                                            size_t namelen),
                 const void *ptr);

/**
 * subst_getenv: callback function for str_expand to get variables from environ
 * @defaults: pointer to a NULL-terminated array of pointers to strings in the
 * style of environ, providing default values for variables not found in the
 * environment, or NULL if no defaults are to be provided.
 * @name: name of an environment variable (which need not be NUL-terminated)
 * @namelen: length of name
 *
 * This function is a suitable callback for str_expand when variable references
 * are to be resolved using getenv().
 */
const char *subst_getenv(const void *defaults,
                         const char *name,
                         size_t namelen);

#endif /* LIGHTNING_COMMON_UTILS_H */
