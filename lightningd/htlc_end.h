#ifndef LIGHTNING_LIGHTNINGD_HTLC_END_H
#define LIGHTNING_LIGHTNINGD_HTLC_END_H
#include "config.h"
#include <ccan/htable/htable_type.h>
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/htlc_state.h>
#include <common/sphinx.h>
#include <wire/gen_onion_wire.h>

/* We look up HTLCs by channel & id */
struct htlc_key {
	struct channel *channel;
	u64 id;
};

#define HTLC_INVALID_ID (-1ULL)

/* Incoming HTLC */
struct htlc_in {
	/* The database primary key for this htlc. Must be 0 until it
	 * is saved to the database, must be >0 after saving to the
	 * database. */
	u64 dbid;
	struct htlc_key key;
	struct amount_msat msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;

	enum htlc_state hstate;

	/* Onion information */
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];

	/* Shared secret for us to send any failure message (NULL if malformed) */
	struct secret *shared_secret;

	/* If we couldn't decode the onion, this contains the error code.. */
	enum onion_type badonion;

	/* Otherwise, this contains the failure message to send. */
	const struct onionreply *failonion;

	/* If they fulfilled, here's the preimage. */
	struct preimage *preimage;

	/* Remember the timestamp we received this HTLC so we can later record
	 * it, and the resolution time, in the forwards table. */
        struct timeabs received_time;

	/* If it was blinded. */
	struct pubkey *blinding;
	/* Only set if blinding != NULL */
	struct secret blinding_ss;
	/* true if we supplied the preimage */
	bool *we_filled;
};

struct htlc_out {
	/* The database primary key for this htlc. Must be 0 until it
	 * is saved to the database, must be >0 after saving to the
	 * database. */
	u64 dbid;
	struct htlc_key key;
	struct amount_msat msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;

	enum htlc_state hstate;

	/* Onion information */
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];

	/* If a local error, this is non-NULL. */
	const u8 *failmsg;

	/* For a remote error. */
	const struct onionreply *failonion;

	/* If we fulfilled, here's the preimage. */
	/* FIXME: This is basically unused, except as a bool! */
	struct preimage *preimage;

	/* Is this a locally-generated payment?  Implies ->in is NULL. */
	bool am_origin;

	/* If am_origin, this is the partid of the payment. */
	u64 partid;

	/* Where it's from, if not going to us. */
	struct htlc_in *in;

	/* Blinding to send alongside, if any. */
	struct pubkey *blinding;
};

static inline const struct htlc_key *keyof_htlc_in(const struct htlc_in *in)
{
	return &in->key;
}

static inline const struct htlc_key *keyof_htlc_out(const struct htlc_out *out)
{
	return &out->key;
}

size_t hash_htlc_key(const struct htlc_key *htlc_key);

static inline bool htlc_in_eq(const struct htlc_in *in, const struct htlc_key *k)
{
	return in->key.channel == k->channel && in->key.id == k->id;
}

static inline bool htlc_out_eq(const struct htlc_out *out,
			       const struct htlc_key *k)
{
	return out->key.channel == k->channel && out->key.id == k->id;
}


HTABLE_DEFINE_TYPE(struct htlc_in, keyof_htlc_in, hash_htlc_key, htlc_in_eq,
		   htlc_in_map);

HTABLE_DEFINE_TYPE(struct htlc_out, keyof_htlc_out, hash_htlc_key, htlc_out_eq,
		   htlc_out_map);

struct htlc_in *find_htlc_in(const struct htlc_in_map *map,
			     const struct channel *channel,
			     u64 htlc_id);

/* FIXME: Slow function only used at startup. */
struct htlc_in *remove_htlc_in_by_dbid(struct htlc_in_map *remaining_htlcs_in,
				       u64 dbid);

struct htlc_out *find_htlc_out(const struct htlc_out_map *map,
			       const struct channel *channel,
			       u64 htlc_id);

/* You still need to connect_htlc_in this! */
struct htlc_in *new_htlc_in(const tal_t *ctx,
			    struct channel *channel, u64 id,
			    struct amount_msat msat, u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    const struct secret *shared_secret TAKES,
			    const struct pubkey *blinding TAKES,
			    const struct secret *blinding_ss,
			    const u8 *onion_routing_packet);

/* You need to set the ID, then connect_htlc_out this! */
struct htlc_out *new_htlc_out(const tal_t *ctx,
			      struct channel *channel,
			      struct amount_msat msat,
			      u32 cltv_expiry,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      const struct pubkey *blinding,
			      bool am_origin,
			      u64 partid,
			      struct htlc_in *in);

void connect_htlc_in(struct htlc_in_map *map, struct htlc_in *hin);
void connect_htlc_out(struct htlc_out_map *map, struct htlc_out *hout);

/* Set up hout->in to be hin (non-NULL), and clear if hin freed. */
void htlc_out_connect_htlc_in(struct htlc_out *hout, struct htlc_in *hin);

struct htlc_out *htlc_out_check(const struct htlc_out *hout,
				const char *abortstr);
struct htlc_in *htlc_in_check(const struct htlc_in *hin, const char *abortstr);

#endif /* LIGHTNING_LIGHTNINGD_HTLC_END_H */
