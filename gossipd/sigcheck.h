#ifndef LIGHTNING_GOSSIPD_SIGCHECK_H
#define LIGHTNING_GOSSIPD_SIGCHECK_H
#include "config.h"
#include <common/node_id.h>

/* Returns error msg if signature wrong, else NULL */
const char *sigcheck_channel_update(const tal_t *ctx,
				    const struct node_id *node_id,
				    const secp256k1_ecdsa_signature *node_sig,
				    const u8 *update);

/* Returns error msg if signature wrong, else NULL */
const char *sigcheck_channel_announcement(const tal_t *ctx,
					  const struct node_id *node1_id,
					  const struct node_id *node2_id,
					  const struct pubkey *bitcoin1_key,
					  const struct pubkey *bitcoin2_key,
					  const secp256k1_ecdsa_signature *node1_sig,
					  const secp256k1_ecdsa_signature *node2_sig,
					  const secp256k1_ecdsa_signature *bitcoin1_sig,
					  const secp256k1_ecdsa_signature *bitcoin2_sig,
					  const u8 *announcement);

/* Returns error msg if signature wrong, else NULL */
const char *sigcheck_node_announcement(const tal_t *ctx,
				       const struct node_id *node_id,
				       const secp256k1_ecdsa_signature *node_sig,
				       const u8 *node_announcement);
#endif /* LIGHTNING_GOSSIPD_SIGCHECK_H */
