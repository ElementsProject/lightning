#include "config.h"
#include <assert.h>
#include <ccan/ccan/err/err.h>
#include <ccan/ccan/htable/htable.h>
#include <common/autodata.h>
#include <common/setup.h>
#include <common/utils.h>
#include <sodium.h>
#include <wally_core.h>

static void *cln_wally_tal(size_t size)
{
	assert(wally_tal_ctx);
	return tal_arr_label(wally_tal_ctx, u8, size, "cln_wally_tal");
}

static void cln_wally_free(void *ptr)
{
	tal_free(ptr);
}

static struct wally_operations wally_tal_ops = {
	.struct_size = sizeof(struct wally_operations),
	.malloc_fn = cln_wally_tal,
	.free_fn = cln_wally_free,
};

static void *htable_tal(struct htable *ht, size_t len)
{
	return tal_arrz(ht, u8, len);
}

static void htable_tal_free(struct htable *ht, void *p)
{
	tal_free(p);
}

void common_setup(const char *argv0)
{
	int wally_ret;

	setup_locale();
	err_set_progname(argv0);

	/* We rely on libsodium for some of the crypto stuff, so we'd better
	 * not start if it cannot do its job correctly. */
	if (sodium_init() == -1)
		errx(1, "Could not initialize libsodium. Maybe not enough entropy"
		     " available ?");

	/* We set up Wally, the bitcoin wallet lib */
	wally_ret = wally_init(0);
	if (wally_ret != WALLY_OK)
		errx(1, "Error initializing libwally: %i", wally_ret);
	wally_ret = wally_set_operations(&wally_tal_ops);
	if (wally_ret != WALLY_OK)
		errx(1, "Error setting libwally operations: %i", wally_ret);
	secp256k1_ctx = wally_get_secp_context();

	/* Make htable* use tal for the tables themselves. */
	htable_set_allocator(htable_tal, htable_tal_free);

	setup_tmpctx();
}

void common_shutdown(void)
{
	const char *p = taken_any();
	if (p)
		errx(1, "outstanding taken(): %s", p);
	take_cleanup();
	tal_free(tmpctx);
	wally_cleanup(0);
	tal_free(wally_tal_ctx);
	autodata_cleanup();
}
