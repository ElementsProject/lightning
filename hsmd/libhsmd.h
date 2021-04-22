#ifndef LIGHTNING_HSMD_LIBHSMD_H
#define LIGHTNING_HSMD_LIBHSMD_H

#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/node_id.h>
#include <common/status_levels.h>
#include <hsmd/hsmd_wiregen.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>
#include <wally_bip32.h>

/*~ A struct that holds some context about the origin of an
 * incoming request. It can either be a main daemon client, which is
 * not associated with a peer or channel, or a peer client, which does
 * have an association. */
struct hsmd_client {
	/*~ Useful for logging, but also used to derive the per-channel seed. */
	struct node_id id;

	/*~ This is a unique value handed to us from lightningd, used for
	 * per-channel seed generation (a single id may have multiple channels
	 * over time).
	 *
	 * It's actually zero for the initial lightningd client connection and
	 * the ones for gossipd and connectd, which don't have channels
	 * associated. */
	u64 dbid;

	/* What is this client allowed to ask for? */
	u64 capabilities;

	/* Params to apply to all transactions for this client */
	const struct chainparams *chainparams;

	/* A pointer to extra context that is to be passed around with
	 * the request. Used in `hsmd` to determine which connection
	 * originated the request. It is passed to the `hsmd_status_*`
	 * functions to allow reporting errors to the client. */
	void *extra;
};

struct hsmd_client *hsmd_client_new_main(const tal_t *ctx, u64 capabilities,
					 void *extra);

struct hsmd_client *hsmd_client_new_peer(const tal_t *ctx, u64 capabilities,
					 u64 dbid,
					 const struct node_id *peer_id,
					 void *extra);

/* Handle an incoming request with the provided context. Upon
 * successful processing we return a response message that is
 * allocated off of `ctx`. Failures return a `NULL` pointer, and the
 * failure details were passed to `hsmd_failed`. */
u8 *hsmd_handle_client_message(const tal_t *ctx, struct hsmd_client *client,
			       const u8 *msg);

/* Functions to report debugging information or errors. These must be
 * implemented by the user of the library. */
u8 *hsmd_status_bad_request(struct hsmd_client *client, const u8 *msg,
			    const char *error);

/* Send a printf-style debugging trace. */
void hsmd_status_fmt(enum log_level level,
		const struct node_id *peer,
		const char *fmt, ...)
	PRINTF_FMT(3,4);

#define hsmd_status_debug(...)				\
	hsmd_status_fmt(LOG_DBG, NULL, __VA_ARGS__)
#define hsmd_status_broken(...)				\
	hsmd_status_fmt(LOG_BROKEN, NULL, __VA_ARGS__)

void hsmd_status_failed(enum status_failreason code,
			const char *fmt, ...) PRINTF_FMT(2,3);

/* The following declarations are here only temporarily while we migrate logic from hsmd.c to libhsmd.c */

/*~ Nobody will ever find it here!  hsm_secret is our root secret, the bip32
 * tree and bolt12 payer_id keys are derived from that, and cached here. */
/* TODO: Move into the libhsmd.c file as soon as hsmd.c doesn't need
 * it anymore. */
struct {
	struct secret hsm_secret;
	struct ext_key bip32;
	secp256k1_keypair bolt12;
} secretstuff;

bool check_client_capabilities(struct hsmd_client *client, enum hsmd_wire t);

/* end of temporary global declarations. The above will be removed once we complete the migration. */
#endif /* LIGHTNING_HSMD_LIBHSMD_H */
