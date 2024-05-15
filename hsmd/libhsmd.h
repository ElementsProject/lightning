#ifndef LIGHTNING_HSMD_LIBHSMD_H
#define LIGHTNING_HSMD_LIBHSMD_H

#include "config.h"
#include <common/node_id.h>
#include <common/status_levels.h>
#include <hsmd/hsmd_wiregen.h>

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

/* Given the (unencrypted) base secret, intialize all derived secrets.
 *
 * While we ensure that the memory the internal secrets are stored in
 * is secure (mlock), the caller must make sure that the `hsm_secret`
 * argument is handled securely before this call to avoid potential
 * issues. The function copies the secret, so the caller can free the
 * secret after the call.
 *
 * Returns the `hsmd_init_reply` with the information required by
 * `lightningd`.
 */
u8 *hsmd_init(struct secret hsm_secret, const u64 hsmd_version,
	      struct bip32_key_version bip32_key_version);

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

/* Given a message type and a client that sent the message, determine
 * whether the client was permitted to send such a message. */
bool hsmd_check_client_capabilities(struct hsmd_client *client,
				    enum hsmd_wire t);

/* The negotiated protocol version ends up in here. */
extern u64 hsmd_mutual_version;

/* If they specify --dev-force-privkey it ends up in here. */
extern struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
extern struct secret *dev_force_bip32_seed;
/* If they specify --dev-hsmd-fail-preapprove it ends up in here. */
extern bool dev_fail_preapprove;
/* If they specify --dev-no-preapprove-check it ends up in here. */
extern bool dev_no_preapprove_check;
#endif /* LIGHTNING_HSMD_LIBHSMD_H */
