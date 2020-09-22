#include "utils.h"
#include <bitcoin/chainparams.h>
#include <ccan/list/list.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <locale.h>

const tal_t *wally_tal_ctx;
secp256k1_context *secp256k1_ctx;
const tal_t *tmpctx;

const struct chainparams *chainparams;

bool is_elements(const struct chainparams *chainparams)
{
	return chainparams->is_elements;
}

/* Steal any wally allocations onto this context. */
void tal_gather_wally(const tal_t *ctx)
{
	tal_t *p;
	assert(tal_first(wally_tal_ctx));
	while ((p = tal_first(wally_tal_ctx)) != NULL)
		tal_steal(ctx, p);
}

#if DEVELOPER
/* If you've got a softref, we assume no reallocs. */
static void dont_move_softref(tal_t *ctx, enum tal_notify_type ntype, void *info)
{
	abort();
}
#endif

static void softref_nullify(tal_t *obj, void **ptr)
{
	*ptr = NULL;
#if DEVELOPER
	tal_del_notifier(obj, dont_move_softref);
#endif
}

static void softref_cleanup(const tal_t *outer, void **ptr)
{
	if (*ptr) {
		tal_del_destructor2(*ptr, softref_nullify, ptr);
	}
#if DEVELOPER
	tal_del_notifier(outer, dont_move_softref);
#endif
}

void set_softref_(const tal_t *outer, size_t outersize, void **ptr, tal_t *obj)
{
	/* pointer is inside outer, right? */
	assert((char *)ptr >= (char *)outer);
	assert((char *)ptr < (char *)outer + outersize);

	/* This is harmless if there was no prior, otherwise constrains the
	 * leak: we don't have enough information in softref_nullify to
	 * clear softref_cleanup */
	tal_del_destructor2(outer, softref_cleanup, ptr);

	if (obj) {
		tal_add_destructor2(outer, softref_cleanup, ptr);
		tal_add_destructor2(obj, softref_nullify, ptr);
#if DEVELOPER
		tal_add_notifier(obj, TAL_NOTIFY_MOVE, dont_move_softref);
#endif
	}

#if DEVELOPER
	tal_add_notifier(outer, TAL_NOTIFY_MOVE, dont_move_softref);
#endif

	*ptr = obj;
}

void clear_softref_(const tal_t *outer, size_t outersize, void **ptr)
{
	assert((char *)ptr >= (char *)outer);
	assert((char *)ptr < (char *)outer + outersize);

	if (*ptr) {
		tal_del_destructor2(outer, softref_cleanup, ptr);
		tal_del_destructor2(*ptr, softref_nullify, ptr);
#if DEVELOPER
		tal_del_notifier(*ptr, dont_move_softref);
#endif
	}

#if DEVELOPER
	tal_del_notifier(outer, dont_move_softref);
#endif

	*ptr = NULL;
}

char *tal_hexstr(const tal_t *ctx, const void *data, size_t len)
{
	char *str = tal_arr(ctx, char, hex_str_size(len));
	hex_encode(data, len, str, hex_str_size(len));
	return str;
}

char *tal_hex(const tal_t *ctx, const tal_t *data)
{
	return tal_hexstr(ctx, data, tal_bytelen(data));
}

u8 *tal_hexdata(const tal_t *ctx, const void *str, size_t len)
{
	u8 *data = tal_arr(ctx, u8, hex_data_size(len));
	if (!hex_decode(str, len, data, hex_data_size(len)))
		return NULL;
	return data;
}

/* Use the POSIX C locale. */
void setup_locale(void)
{
	setlocale(LC_ALL, "C");
	putenv("LC_ALL=C"); /* For exec{l,lp,v,vp}(...) */
}

/* Initial creation of tmpctx. */
void setup_tmpctx(void)
{
	tmpctx = tal_arr_label(NULL, char, 0, "tmpctx");
}

/* Free any children of tmpctx. */
void clean_tmpctx(void)
{
	const tal_t *p;

	/* Don't actually free tmpctx: we hand pointers to it around. */
	while ((p = tal_first(tmpctx)) != NULL)
		tal_free(p);
}

void tal_arr_remove_(void *p, size_t elemsize, size_t n)
{
    // p is a pointer-to-pointer for tal_resize.
    char *objp = *(char **)p;
    size_t len = tal_bytelen(objp);
    assert(len % elemsize == 0);
    assert((n + 1) * elemsize <= len);
    memmove(objp + elemsize * n, objp + elemsize * (n+1),
	    len - (elemsize * (n+1)));
    tal_resize((char **)p, len - elemsize);
}

void *tal_dup_talarr_(const tal_t *ctx, const tal_t *src TAKES, const char *label)
{
	if (!src) {
		/* Correctly handle TAKES on a NULL `src`.  */
		(void) taken(src);
		return NULL;
	}
	return tal_dup_(ctx, src, 1, tal_bytelen(src), 0, label);
}
