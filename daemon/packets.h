#ifndef LIGHTNING_DAEMON_PACKETS_H
#define LIGHTNING_DAEMON_PACKETS_H
#include "config.h"
#include "lightning.pb-c.h"

struct commit_info;
struct htlc;
struct peer;
struct preimage;
struct sha256;

/* Send various kinds of packets */
void queue_pkt_open(struct peer *peer, bool offer_anchor);
void queue_pkt_anchor(struct peer *peer);
void queue_pkt_open_commit_sig(struct peer *peer);
void queue_pkt_open_complete(struct peer *peer);
void queue_pkt_htlc_add(struct peer *peer, struct htlc *htlc);
void queue_pkt_htlc_fulfill(struct peer *peer, struct htlc *htlc);
void queue_pkt_htlc_fail(struct peer *peer, struct htlc *htlc);
void queue_pkt_feechange(struct peer *peer, u64 feerate);
void queue_pkt_commit(struct peer *peer, const secp256k1_ecdsa_signature *sig);
void queue_pkt_revocation(struct peer *peer,
			  const struct sha256 *preimage,
			  const struct sha256 *next_hash);
void queue_pkt_close_shutdown(struct peer *peer);
void queue_pkt_close_signature(struct peer *peer);
void queue_pkt_nested(struct peer *peer, int type, const u8 *nested_pkt);

Pkt *pkt_err(struct peer *peer, const char *msg, ...);
Pkt *pkt_init(struct peer *peer, u64 ack);
void queue_pkt_err(struct peer *peer, Pkt *err);
Pkt *pkt_err_unexpected(struct peer *peer, const Pkt *pkt);

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(struct peer *peer, const Pkt *pkt,
		     struct sha256 *revocation_hash,
		     struct sha256 *next_revocation_hash);

Pkt *accept_pkt_anchor(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt,
				secp256k1_ecdsa_signature *sig);

Pkt *accept_pkt_open_complete(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_htlc_add(struct peer *peer, const Pkt *pkt, struct htlc **h);

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt, struct htlc **h,
			  u8 **fail);

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt, struct htlc **h,
			     struct preimage *r);

Pkt *accept_pkt_update_fee(struct peer *peer, const Pkt *pkt, u64 *feerate);

Pkt *accept_pkt_update_accept(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_commit(struct peer *peer, const Pkt *pkt,
		       secp256k1_ecdsa_signature *sig);

Pkt *accept_pkt_revocation(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_close_shutdown(struct peer *peer, const Pkt *pkt);

#endif /* LIGHTNING_DAEMON_PACKETS_H */
