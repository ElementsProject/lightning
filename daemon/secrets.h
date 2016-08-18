#ifndef LIGHTNING_DAEMON_SECRETS_H
#define LIGHTNING_DAEMON_SECRETS_H
/* Routines to handle private keys. */
#include "config.h"
#include <ccan/short_types/short_types.h>

struct peer;
struct lightningd_state;
struct signature;
struct sha256;

void privkey_sign(struct lightningd_state *dstate, const void *src, size_t len,
		  struct signature *sig);

void peer_sign_theircommit(const struct peer *peer,
			   struct bitcoin_tx *commit,
			   struct signature *sig);

void peer_sign_ourcommit(const struct peer *peer,
			 struct bitcoin_tx *commit,
			 struct signature *sig);

void peer_sign_spend(const struct peer *peer,
		     struct bitcoin_tx *spend,
		     const u8 *commit_witnessscript,
		     struct signature *sig);

void peer_sign_htlc_refund(const struct peer *peer,
			   struct bitcoin_tx *spend,
			   const u8 *htlc_witnessscript,
			   struct signature *sig);

void peer_sign_htlc_fulfill(const struct peer *peer,
			    struct bitcoin_tx *spend,
			    const u8 *htlc_witnessscript,
			    struct signature *sig);

void peer_sign_mutual_close(const struct peer *peer,
			    struct bitcoin_tx *close,
			    struct signature *sig);

void peer_sign_steal_input(const struct peer *peer,
			   struct bitcoin_tx *spend,
			   size_t i,
			   const u8 *witnessscript,
			   struct signature *sig);

const char *peer_secrets_for_db(const tal_t *ctx, struct peer *peer);

void peer_set_secrets_from_db(struct peer *peer,
			      const void *commit_privkey,
			      size_t commit_privkey_len,
			      const void *final_privkey,
			      size_t final_privkey_len,
			      const void *revocation_seed,
			      size_t revocation_seed_len);

void peer_secrets_init(struct peer *peer);

void peer_get_revocation_hash(const struct peer *peer, u64 index,
			      struct sha256 *rhash);
void peer_get_revocation_preimage(const struct peer *peer, u64 index,
				  struct sha256 *preimage);

void secrets_init(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_SECRETS_H */
