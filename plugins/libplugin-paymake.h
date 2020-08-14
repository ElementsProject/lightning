#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_PAYMAKE_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_PAYMAKE_H
#include "config.h"

#include <ccan/take/take.h>
#include <common/json.h>

struct command;
struct payment;
struct payment_modifier;
struct plugin;

/** struct paymake
 *
 * @brief a factory for `struct payment` objects.
 *
 * @desc an opaque type interacted with via the API in this
 * header file.
 * This allows to set up the root of a payment tree.
 */
struct paymake;

/** paymake_global_init
 *
 * @brief must be called in your plugin `init` callback.
 */
void paymake_global_init(struct plugin *, const char *buf, const jsmntok_t *t);

/** paymake_new
 *
 * @brief Create root payment factory.
 *
 * @param ctx - the context to allocate the *factory* from.
 * Note that the root payment constructed by the factory is
 * *not* allocated off this context!
 * It is suggested you use `tmpctx` for this; `struct paymake`
 * is intended as a temporary object.
 * @param cmd - the command to pass to the constructed payment
 * later.
 * May be NULL.
 *
 * @desc This creates a root payment factory whose list of
 * payment modifiers is the canonical list of payment modifiers.
 */
struct paymake *paymake_new(const tal_t *ctx, struct command *cmd);

/** paymake_disable_all_paymods
 *
 * @brief Disable all paymods for the factory.
 * Re-enable with `paymake_enable_paymod`.
 */
void paymake_disable_all_paymods(struct paymake *pm);

/** paymake_disable_paymod
 *
 * @brief Disable a specific named paymod.
 * This will abort() if the name does not match anything
 * canonically known by the `paymake` system, or a new
 * one registered by your plugin.
 */
void paymake_disable_paymod(struct paymake *pm, const char *paymod_name);

/** paymake_enable_paymod
 *
 * @brief Enable a specific named paymod.
 * This will abort() if the name does not match anything
 * canonically known by the `paymake` system, or a new
 * one registered by your plugin.
 */
void paymake_enable_paymod(struct paymake *pm, const char *paymod_name);

/** paymake_disable_mpp_paymods
 *
 * @brief Disable all MPP-related paymods.
 * Re-enable with `paymake_enable_paymod`.
 */
void paymake_disable_mpp_paymods(struct paymake *pm);

/** paymake_disable_amount_fuzz
 *
 * @brief Disable amount fuzzing at the shadow route paymod,
 * if the paymod is enabled.
 */
void paymake_disable_amount_fuzz(struct paymake *pm);

/** paymake_prepend_paymod
 *
 * @brief Prepend a non-standard payment modifier to the
 * current list of payment modifiers.
 * Also implicitly enables the given paymod.
 */
void paymake_prepend_paymod(struct paymake *pm,
			    const char *paymod_name TAKES,
			    struct payment_modifier *paymod);

/** paymake_append_paymod
 *
 * @brief Append a non-standard payment modifier to the
 * current list of payment modifiers.
 * Also implicitly enables the given paymod.
 */
void paymake_append_paymod(struct paymake *pm,
			   const char *paymod_name TAKES,
			   struct payment_modifier *paymod);

/** paymake_create
 *
 * @brief Construct the root payment.
 * After this call, the `struct paymake` is now unusable
 * and can only be `tal_free`d.
 *
 * @param ctx - the context to allocate the `struct payment`
 * off of.
 * @param pm - the factory whose parameters are to be used for
 * constructing the root payment.
 */
struct payment *paymake_create(const tal_t *ctx, struct paymake *pm);

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_PAYMAKE_H */
