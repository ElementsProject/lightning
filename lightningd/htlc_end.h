#ifndef LIGHTNING_LIGHTNINGD_HTLC_END_H
#define LIGHTNING_LIGHTNINGD_HTLC_END_H
#include "config.h"
#include <ccan/htable/htable_type.h>
#include <ccan/short_types/short_types.h>
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
	u64 msatoshi;
	u32 cltv_expiry;
	struct sha256 payment_hash;

	enum htlc_state hstate;

	/* Onion information */
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];

	/* Shared secret for us to send any failure message. */
	struct secret shared_secret;

	/* If a local error, this is non-zero. */
	enum onion_type failcode;

	/* For a remote error. */
	const u8 *failuremsg;

	/* If failcode & UPDATE, this is the channel which failed. */
	struct short_channel_id failoutchannel;

	/* If they fulfilled, here's the preimage. */
	struct preimage *preimage;

};

struct htlc_out {
	/* The database primary key for this htlc. Must be 0 until it
	 * is saved to the database, must be >0 after saving to the
	 * database. */
	u64 dbid;
	u64 origin_htlc_id;
	struct htlc_key key;
	u64 msatoshi;
	u32 cltv_expiry;
	struct sha256 payment_hash;

	enum htlc_state hstate;

	/* Onion information */
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];

	/* If a local error, this is non-zero. */
	enum onion_type failcode;

	/* For a remote error. */
	const u8 *failuremsg;

	/* If we fulfilled, here's the preimage. */
	struct preimage *preimage;

	/* Where it's from, if not going to us. */
	struct htlc_in *in;
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

struct htlc_out *find_htlc_out(const struct htlc_out_map *map,
			       const struct channel *channel,
			       u64 htlc_id);

/* You still need to connect_htlc_in this! */
struct htlc_in *new_htlc_in(const tal_t *ctx,
			    struct channel *channel, u64 id,
			    u64 msatoshi, u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    const struct secret *shared_secret,
			    const u8 *onion_routing_packet);

/* You need to set the ID, then connect_htlc_out this! */
struct htlc_out *new_htlc_out(const tal_t *ctx,
			      struct channel *channel,
			      u64 msatoshi, u32 cltv_expiry,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in);

void connect_htlc_in(struct htlc_in_map *map, struct htlc_in *hin);
void connect_htlc_out(struct htlc_out_map *map, struct htlc_out *hout);

struct htlc_out *htlc_out_check(const struct htlc_out *hout,
				const char *abortstr);
struct htlc_in *htlc_in_check(const struct htlc_in *hin, const char *abortstr);

#if DEVELOPER
struct htable;
void htlc_inmap_mark_pointers_used(struct htable *memtable,
				   const struct htlc_in_map *map);
void htlc_outmap_mark_pointers_used(struct htable *memtable,
				   const struct htlc_out_map *map);
#endif /* DEVELOPER */
#endif /* LIGHTNING_LIGHTNINGD_HTLC_END_H */
