#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/utf8/utf8.h>
#include <common/utils.h>
#include <errno.h>
#include <locale.h>

const tal_t *wally_tal_ctx;
secp256k1_context *secp256k1_ctx;
const tal_t *tmpctx;

const struct chainparams *chainparams;

bool is_elements(const struct chainparams *chainparams)
{
	return chainparams->is_elements;
}

void tal_wally_start(void)
{
	if (wally_tal_ctx) {
		/* This makes valgrind show us backtraces! */
		*(u8 *)wally_tal_ctx = '\0';
		abort();
	}

	wally_tal_ctx = tal_arr(NULL, char, 0);
}

void tal_wally_end(const tal_t *parent)
{
	tal_t *p;
	while ((p = tal_first(wally_tal_ctx)) != NULL) {
		/* Refuse to make a loop! */
		assert(p != parent);
		/* Don't steal backtrace from wally_tal_ctx! */
		if (tal_name(p) && streq(tal_name(p), "backtrace")) {
			tal_free(p);
			continue;
		}
		tal_steal(parent, p);
	}
	wally_tal_ctx = tal_free(wally_tal_ctx);
}

void tal_wally_end_onto_(const tal_t *parent,
			 tal_t *from_wally,
			 const char *from_wally_name)
{
	if (from_wally)
		tal_set_name_(from_wally, from_wally_name, 1);
	tal_wally_end(tal_steal(parent, from_wally));
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

bool tal_arr_eq_(const void *a, const void *b, size_t unused)
{
	return memeq(a, tal_bytelen(a), b, tal_bytelen(b));
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

/* Check for valid UTF-8 */
bool utf8_check(const void *vbuf, size_t buflen)
{
	const u8 *buf = vbuf;
	struct utf8_state utf8_state = UTF8_STATE_INIT;
	bool need_more = false;

	for (size_t i = 0; i < buflen; i++) {
		if (!utf8_decode(&utf8_state, buf[i])) {
			need_more = true;
			continue;
		}
		need_more = false;
		if (errno != 0)
			return false;
	}
	return !need_more;
}

char *utf8_str(const tal_t *ctx, const u8 *buf TAKES, size_t buflen)
{
	char *ret;

	if (!utf8_check(buf, buflen)) {
		if (taken(buf))
			tal_free(buf);
		return NULL;
	}

	/* Add one for nul term */
	ret = tal_dup_arr(ctx, char, (const char *)buf, buflen, 1);
	ret[buflen] = '\0';
	return ret;
}

char *tal_strdup_or_null(const tal_t *ctx, const char *str)
{
	if (!str) {
		/* You might have taken NULL; that's legal!  Release now. */
		taken(str);
		return NULL;
	}
	return tal_strdup(ctx, str);
}

int tmpdir_mkstemp(const tal_t *ctx, const char *template TAKES, char **created)
{
	char *tmpdir = getenv("TMPDIR");
	char *path = path_join(ctx, tmpdir ?: "/tmp", template);
	int fd = mkstemp(path);

	if (fd >= 0)
		*created = path;
	else
		tal_free(path);

	return fd;
}

char *str_lowering(const void *ctx, const char *string TAKES)
{
	char *ret;

	ret = tal_strdup(ctx, string);
	for (char *p = ret; *p; p++) *p = tolower(*p);
	return ret;
}
