#include "libplugin-paymake.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <plugins/libplugin-pay.h>
#include <stdlib.h>
#include <string.h>

struct paymod_desc {
	const char *name;
	struct payment_modifier *mod;
	bool disabled;
};

/* Canonical list of paymods in the correct order they should run in.  */
static const struct paymod_desc canonical_paymods[] = {
	{"local_channel_hints", &local_channel_hints_pay_mod},
	{"exemptfee", &exemptfee_pay_mod},
	{"directpay", &directpay_pay_mod},
	{"shadowroute", &shadowroute_pay_mod},
	/* These two paymods must be executed in the exact order
	 * specified below.
	 */
	{"routehints", &routehints_pay_mod},
	{"presplit", &presplit_pay_mod},
	{"waitblockheight", &waitblockheight_pay_mod},
	{"retry", &retry_pay_mod},
	{"adaptive_splitter", &adaptive_splitter_pay_mod}
};
/* Canonical list of paymods involved in MPP.  */
static const char *const mpp_paymods[] = {
	"presplit",
	"adaptive_splitter"
};

/* List of paymods to disable no matter what.  */
static char **dev_disable_paymods = NULL;

/* Create an initial copy of the paymods.  */
static struct paymod_desc *
initial_paymod_list(const tal_t *ctx)
{
	struct paymod_desc *rv = tal_dup_arr(ctx, struct paymod_desc,
					     canonical_paymods,
					     ARRAY_SIZE(canonical_paymods),
					     0);
	for (size_t i = 0; i < tal_count(rv); ++i)
		rv[i].disabled = false;
	return rv;
}

/* Determine if the named paymod is in the list of dev-disabled
 * paymods.  */
static inline bool is_dev_disabled_paymod(const char *name)
{
#if DEVELOPER
	for (size_t i = 0; i < tal_count(dev_disable_paymods); ++i)
		if (streq(name, dev_disable_paymods[i]))
			return true;
#endif
	return false;
}

/* From a list of paymods descriptions, create a sequenced list of
 * paymods.  */
static struct payment_modifier **
finalize_paymod_list(const tal_t *ctx,
		     const struct paymod_desc *paymod_list TAKES)
{
	struct payment_modifier **rv = tal_arr(ctx, struct payment_modifier *,
					       0);

	for (size_t i = 0; i < tal_count(paymod_list); ++i) {
		if (is_dev_disabled_paymod(paymod_list[i].name))
			continue;
		if (!paymod_list[i].disabled)
			tal_arr_expand(&rv, paymod_list[i].mod);
	}
	/* Add NULL terminator.  */
	tal_arr_expand(&rv, NULL);

	if (taken(paymod_list))
		tal_free(paymod_list);
	return rv;
}

void paymake_global_init(struct plugin *plugin,
			 const char *buf, const jsmntok_t *t)
{
	dev_disable_paymods = tal_arr(NULL, char *, 0);
#if DEVELOPER
	const char *field;
	const jsmntok_t *array, *entry;
	bool valid;
	size_t i;

	field = rpc_delve(tmpctx, plugin, "listconfigs",
			  take(json_out_obj(NULL,
					    "config", "dev-disable-paymods")),
			  ".dev-disable-paymods");
	assert(field);
	array = json_parse_input(tmpctx, field, strlen(field), &valid);
	assert(array && valid);
	json_for_each_arr (i, entry, array)
		tal_arr_expand(&dev_disable_paymods,
			       json_strdup(NULL, field, entry));
#endif
}

struct paymake {
	struct command *cmd;

	struct paymod_desc *paymod_list;

	bool fuzz_amount;
};

struct paymake *paymake_new(const tal_t *ctx, struct command *cmd)
{
	struct paymake *pm = tal(ctx, struct paymake);
	pm->cmd = cmd;
	pm->paymod_list = initial_paymod_list(pm);
	pm->fuzz_amount = true;
	return pm;
}

struct payment *paymake_create(const tal_t *ctx, struct paymake *pm)
{
	struct payment_modifier **mods;
	struct payment *p;
	bool remove_fuzz_amount = false;

	if (!pm->paymod_list)
		/* Misuse of API.  */
		abort();

	/* Check if the shadowroute paymod is enabled.
	 * If it is not enabled anyway, no amount fuzzing
	 * will happen either.  */
	if (!pm->fuzz_amount && !is_dev_disabled_paymod("shadowroute")) {
		for (size_t i = 0; i < tal_count(pm->paymod_list); ++i) {
			if (pm->paymod_list[i].disabled)
				continue;
			if (pm->paymod_list[i].mod != &shadowroute_pay_mod)
				continue;
			/* Paymod is not disabled and is the shadowroute
			 * paymod, so we should remove amount fuzzing from
			 * its data later after construction.  */
			remove_fuzz_amount = true;
			break;
		}
	}

	mods = finalize_paymod_list(tmpctx, take(pm->paymod_list));
	/* Prevent this paymake from being used in the future.  */
	pm->paymod_list = NULL;

	p = payment_new(ctx, pm->cmd, NULL, mods);
	/* Give responsibility of the payment modifiers array to the
	 * payment.  */
	tal_steal(p, mods);

	/* Modify the fuzz_amount field of shadowroute, if appropriate.  */
	if (remove_fuzz_amount)
		payment_mod_shadowroute_get_data(p)->fuzz_amount = false;

	return p;
}

void paymake_disable_all_paymods(struct paymake *pm)
{
	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();

	for (size_t i = 0; i < tal_count(pm->paymod_list); ++i)
		pm->paymod_list[i].disabled = true;
}

void paymake_disable_paymod(struct paymake *pm, const char *paymod_name)
{
	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();

	for (size_t i = 0; i < tal_count(pm->paymod_list); ++i)
		if (streq(paymod_name, pm->paymod_list[i].name)) {
			pm->paymod_list[i].disabled = true;
			return;
		}

	/* Unknown name, misuse of API.  */
	abort();
}

void paymake_enable_paymod(struct paymake *pm, const char *paymod_name)
{
	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();

	for (size_t i = 0; i < tal_count(pm->paymod_list); ++i)
		if (streq(paymod_name, pm->paymod_list[i].name)) {
			pm->paymod_list[i].disabled = false;
			return;
		}

	/* Unknown name, misuse of API.  */
	abort();
}

void paymake_disable_mpp_paymods(struct paymake *pm)
{
	for (size_t i = 0; i < ARRAY_SIZE(mpp_paymods); ++i)
		paymake_disable_paymod(pm, mpp_paymods[i]);
}

void paymake_disable_amount_fuzz(struct paymake *pm)
{
	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();
	pm->fuzz_amount = false;
}

void paymake_prepend_paymod(struct paymake *pm,
			    const char *paymod_name TAKES,
			    struct payment_modifier *paymod)
{
	struct paymod_desc desc;

	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();

	desc.name = tal_strdup(pm, paymod_name);
	desc.mod = paymod;
	desc.disabled = false;

	/* Prepend.  */
	tal_resize(&pm->paymod_list, tal_count(pm->paymod_list) + 1);
	memmove(&pm->paymod_list[1], &pm->paymod_list[0],
		(tal_count(pm->paymod_list) - 1) * sizeof(*pm->paymod_list));
	pm->paymod_list[0] = desc;
}

void paymake_append_paymod(struct paymake *pm,
			   const char *paymod_name TAKES,
			   struct payment_modifier *paymod)
{
	struct paymod_desc desc;

	if (!pm->paymod_list)
		/* Misuse of API.
		 * This function MUST NOT be used after paymake_create.
		 * which specifically clears pm->paymod_list.
		 */
		abort();

	desc.name = tal_strdup(pm, paymod_name);
	desc.mod = paymod;
	desc.disabled = false;

	/* Append.  */
	tal_arr_expand(&pm->paymod_list, desc);
}
