#include "config.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <common/blindedpath.h>
#include <common/onion_message.h>
#include <common/sphinx.h>
#include <sodium.h>
#include <wire/onion_wire.h>

struct tlv_encrypted_data_tlv **new_encdata_tlvs(const tal_t *ctx,
						 const struct pubkey *ids,
						 const struct short_channel_id **scids)
{
	struct tlv_encrypted_data_tlv **etlvs;

	etlvs = tal_arr(ctx, struct tlv_encrypted_data_tlv *, tal_count(ids));
	for (size_t i = 0; i < tal_count(etlvs); i++) {
		etlvs[i] = tlv_encrypted_data_tlv_new(etlvs);
		if (i+1 < tal_count(scids) && scids[i+1]) {
			etlvs[i]->short_channel_id = tal_dup(etlvs[i],
							     struct short_channel_id,
							     scids[i+1]);
		} else if (i + 1 < tal_count(ids)) {
			etlvs[i]->next_node_id = tal_dup(etlvs[i],
							 struct pubkey,
							 &ids[i+1]);
		}
	}
	return etlvs;
}

/* We can extract nodeid from ids[], but usually we can get it from the
 * previous next_node_id. */
static const struct pubkey *
get_nodeid(const struct tlv_encrypted_data_tlv **tlvs,
	   const struct pubkey *ids,
	   size_t i)
{
	if (i == 0)
		return &ids[0];

	if (tlvs[i-1]->next_node_id == NULL) {
		/* If you didn't set next_node_id you have to set
		 * short_channel_id! */
		assert(tlvs[i-1]->short_channel_id);
		assert(i < tal_count(ids));
		return &ids[i];
	}

	return tlvs[i-1]->next_node_id;
}

/* Stage 1: tlv_encrypted_data_tlv[] -> struct blinded_path.
 * Optional array of node_ids, consulted iff tlv uses scid in one entry. */
struct blinded_path *blinded_path_from_encdata_tlvs(const tal_t *ctx,
						    const struct tlv_encrypted_data_tlv **tlvs,
						    const struct pubkey *ids)
{
	struct privkey first_blinding, blinding_iter;
	struct blinded_path *path;
	size_t nhops = tal_count(ids);
	const struct pubkey *nodeid;

	path = tal(ctx, struct blinded_path);

	assert(nhops > 0);
	assert(tal_count(ids) > 0);

	randombytes_buf(&first_blinding, sizeof(first_blinding));
	if (!pubkey_from_privkey(&first_blinding, &path->first_path_key))
		abort();
	sciddir_or_pubkey_from_pubkey(&path->first_node_id, &ids[0]);

	path->path = tal_arr(ctx, struct onionmsg_hop *, nhops);

	blinding_iter = first_blinding;
	for (size_t i = 0; i < nhops; i++) {
		nodeid = get_nodeid(tlvs, ids, i);

		path->path[i] = tal(path->path, struct onionmsg_hop);
		path->path[i]->encrypted_recipient_data
			= encrypt_tlv_encrypted_data(path->path[i],
						     &blinding_iter,
						     nodeid,
						     tlvs[i],
						     &blinding_iter,
						     &path->path[i]->blinded_node_id);
	}

	return path;
}

/* Stage 2: turn struct blinded_path into array of tlv_onionmsg_tlv.
 * You normally then add fields to the final tlv_onionmsg_tlv. */
struct tlv_onionmsg_tlv **onionmsg_tlvs_from_blinded_path(const tal_t *ctx,
							  const struct blinded_path *bpath)
{
	size_t nhops = tal_count(bpath->path);
	struct tlv_onionmsg_tlv **otlvs = tal_arr(ctx, struct tlv_onionmsg_tlv *, nhops);

	for (size_t i = 0; i < nhops; i++) {
		otlvs[i] = tlv_onionmsg_tlv_new(otlvs);
		otlvs[i]->encrypted_recipient_data
			= tal_dup_talarr(otlvs[i], u8,
					 bpath->path[i]->encrypted_recipient_data);
	}

	return otlvs;
}

/* Stage 3: linearize each struct tlv_onionmsg_tlv into sphinx_hops (taking ids from bpath) */
struct sphinx_hop **onionmsg_tlvs_to_hops(const tal_t *ctx,
					  const struct blinded_path *bpath,
					  const struct tlv_onionmsg_tlv **tlvs)
{
	size_t nhops = tal_count(tlvs);
	struct sphinx_hop **hops = tal_arr(ctx, struct sphinx_hop *, nhops);

	assert(tal_count(bpath->path) == nhops);
	for (size_t i = 0; i < nhops; i++) {
		u8 *payload;
		hops[i] = tal(hops, struct sphinx_hop);
		hops[i]->pubkey = bpath->path[i]->blinded_node_id;
		/* We use a temporary here since ->raw_payload is const */
		payload = tal_arr(hops[i], u8, 0);
		towire_tlv_onionmsg_tlv(&payload, tlvs[i]);
		hops[i]->raw_payload = payload;
	}

	return hops;
}

struct blinded_path *incoming_message_blinded_path(const tal_t *ctx,
						   const struct pubkey *ids,
						   const struct short_channel_id **scids,
						   const struct secret *path_secret)
{
	struct tlv_encrypted_data_tlv **etlvs;
	size_t nhops = tal_count(ids);

	assert(nhops > 0);
	etlvs = new_encdata_tlvs(tmpctx, ids, scids);

	/* Put path_secret into final hop (us) */
	etlvs[nhops-1]->path_id = tal_dup_arr(etlvs[nhops-1], u8,
					      path_secret->data,
					      ARRAY_SIZE(path_secret->data), 0);

	return blinded_path_from_encdata_tlvs(ctx,
					      cast_const2(const struct tlv_encrypted_data_tlv **, etlvs),
					      ids);
}

static void extend_blinded_path(struct blinded_path *bpath,
				const struct onionmsg_hop *hop)
{
	struct onionmsg_hop *newhop = tal(bpath->path, struct onionmsg_hop);
        newhop->blinded_node_id = hop->blinded_node_id;
	newhop->encrypted_recipient_data = tal_dup_talarr(newhop, u8, hop->encrypted_recipient_data);
	tal_arr_expand(&bpath->path, newhop);
}

struct onion_message *outgoing_onion_message(const tal_t *ctx,
					     const struct pubkey *ids,
					     const struct short_channel_id **scids,
					     const struct blinded_path *their_path,
					     struct tlv_onionmsg_tlv *final_tlv STEALS)
{
	struct onion_message *omsg;
	struct blinded_path *our_path;
	const struct blinded_path *combined_path;
	struct tlv_encrypted_data_tlv **etlvs = new_encdata_tlvs(tmpctx, ids, scids);
	struct tlv_onionmsg_tlv **otlvs;

	assert(tal_count(ids) > 0);

	if (their_path) {
		struct tlv_encrypted_data_tlv *pre_final;

		/* Path must lead to blinded path! */
		if (their_path->first_node_id.is_pubkey)
			assert(pubkey_eq(&ids[tal_count(ids)-1], &their_path->first_node_id.pubkey));

		/* If we don't actually have any path, it's all them. */
		if (tal_count(ids) == 1) {
			combined_path = their_path;
			goto wrap;
		}

		/* We need to tell last hop to hand blinded_path blinding for next hop */
		pre_final = etlvs[tal_count(ids)-2];
		pre_final->next_path_key_override = tal_dup(pre_final,
							    struct pubkey,
							    &their_path->first_path_key);
	}

	our_path = blinded_path_from_encdata_tlvs(tmpctx,
						  cast_const2(const struct tlv_encrypted_data_tlv **, etlvs),
						  ids);

	/* Extend with their blinded path if there is one */
	if (their_path) {
		/* Remove final one, since it's actually the first one in blinded path. */
		tal_resize(&our_path->path, tal_count(our_path->path)-1);
		for (size_t i = 0; i < tal_count(their_path->path); i++)
			extend_blinded_path(our_path, their_path->path[i]);
	}

	combined_path = our_path;

wrap:
	/* Now wrap in onionmsg_tlvs */
	otlvs = onionmsg_tlvs_from_blinded_path(tmpctx, combined_path);

	/* Transfer encrypted blob into final tlv, and use it to replace last tlv */
	final_tlv->encrypted_recipient_data = tal_steal(final_tlv, otlvs[tal_count(otlvs)-1]->encrypted_recipient_data);
	tal_free(otlvs[tal_count(otlvs)-1]);
	otlvs[tal_count(otlvs)-1] = tal_steal(otlvs, final_tlv);

	/* Now populate the onion message to return */
	omsg = tal(ctx, struct onion_message);
	omsg->first_blinding = combined_path->first_path_key;
	omsg->hops = onionmsg_tlvs_to_hops(omsg, combined_path,
					   cast_const2(const struct tlv_onionmsg_tlv **, otlvs));
	return omsg;
}
