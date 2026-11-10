#include "config.h"
#include <common/derive_basepoints.h>
#include <common/hsm_secret.h>
#include <common/key_derive.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <tools/hsmtool-recoverhtlc.h>
#include <tools/lightning-hsmtool.h>

static bool derive_channel_basepoints(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys,
	struct secret *htlc_basepoint_secret)
{
	struct secret hsm_secret, channel_seed;
	struct hsm_secret *hsms
		= hsmtool_load_hsm_secret(tmpctx, hsm_secret_path);

	/* Channel derivation always uses the first 32 bytes. */
	memcpy(hsm_secret.data, hsms->secret_data, sizeof(hsm_secret.data));
	derive_channel_seed(&channel_seed, hsm_secret.data,
			    peer_id, channel_dbid);

	if (!derive_htlc_basepoint(&channel_seed, &keys->our_htlc_basepoint,
				   htlc_basepoint_secret))
		return false;
	return derive_revocation_basepoint(&channel_seed,
					   &keys->our_revocation_basepoint,
					   NULL);
}

/* Derive keys to spend our HTLC outputs on the peer's commitment. */
bool hsmtool_recoverhtlc_derive_keys(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const struct pubkey *commitment_point,
	const struct pubkey *remote_htlc_basepoint,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys)
{
	struct secret htlc_basepoint_secret;

	if (!derive_channel_basepoints(peer_id, channel_dbid, hsm_secret_path,
				       keys, &htlc_basepoint_secret))
		return false;

	/* BOLT #3:
	 *
	 * pubkey = basepoint
	 *	    + SHA256(per_commitment_point || basepoint) * G
	 */
	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &keys->our_htlc_basepoint,
				   commitment_point,
				   &keys->our_htlc_privkey)
	    || !derive_simple_key(&keys->our_htlc_basepoint,
				  commitment_point,
				  &keys->our_htlc_key)
	    || !derive_simple_key(remote_htlc_basepoint,
				  commitment_point,
				  &keys->their_htlc_key))
		return false;

	/* Peer commitment: our basepoint, their commitment point. */
	return derive_revocation_key(&keys->our_revocation_basepoint,
				     commitment_point,
				     &keys->revocation_key);
}
