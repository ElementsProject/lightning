#ifndef LIGHTNING_COMMON_UTILS_H
#define LIGHTNING_COMMON_UTILS_H
#include "config.h"
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

extern secp256k1_context *secp256k1_ctx;

extern const struct chainparams *chainparams;

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

/* Macro to set memberptr in tal object outer to point to tal object obj,
 * if it isn't NULL.
 * The 0*sizeof() checks that *memberptr = obj is valid */
#define set_softref(outer, memberptr, obj)				\
	set_softref_((outer), sizeof(*(outer)) + 0*sizeof(*(memberptr) = obj), \
		     (void **)(memberptr), (obj))

/* Macro to clear a (set) softref ptr to NULL  */
#define clear_softref(outer, memberptr)					\
	clear_softref_((outer), sizeof(*(outer)), (void **)(memberptr))

void set_softref_(const tal_t *outer, size_t outersize, void **ptr, tal_t *obj);
void clear_softref_(const tal_t *outer, size_t outersize, void **ptr);

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
 * their position in memory, so only use this for arrays of pointers.
 */
#define tal_arr_remove(p, n) tal_arr_remove_((p), sizeof(**p), (n))
void tal_arr_remove_(void *p, size_t elemsize, size_t n);

/**
 * The comon case of duplicating an entire tal array.
 *
 * A macro because we must not double-evaluate p.
 */
#define tal_dup_talarr(ctx, type, p)					\
	((type *)tal_dup_talarr_((ctx), tal_typechk_(p, type *),	\
				 TAL_LABEL(type, "[]")))
void *tal_dup_talarr_(const tal_t *ctx, const tal_t *src TAKES,
		      const char *label);

/* Check for valid UTF-8 */
bool utf8_check(const void *buf, size_t buflen);

/* Check it's UTF-8, return copy (or same if TAKES), or NULL if not valid. */
char *utf8_str(const tal_t *ctx, const u8 *buf TAKES, size_t buflen);

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
/* Then call this to reparent everything onto this parent (which must
 * have been tal_steal() if it was allocated by libwally here) */
void tal_wally_end(const tal_t *parent);

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

#if EXPERIMENTAL_FEATURES
/* Make sure that nondev is evaluated, and valid, but is a constant */
#define IFEXPERIMENTAL(exp, nonexp) (0 ? (nonexp) : (exp))
#else
#define IFEXPERIMENTAL(exp, nonexp) (nonexp)
#endif

/* Context which all wally allocations use (see common/setup.c) */
extern const tal_t *wally_tal_ctx;

#endif /* LIGHTNING_COMMON_UTILS_H */
