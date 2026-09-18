#include "config.h"
#include <bitcoin/script.h>
#include <common/gossip_constants.h>
#include <common/setup.h>
#include <fcntl.h>
#include <signal.h>
#include <tests/fuzz/libfuzz.h>

/* Give each fuzz process its own gossip_store path so parallel
 * libFuzzer jobs don't race on the same file. */
static char *gossip_store_filename;
#undef GOSSIP_STORE_FILENAME
#define GOSSIP_STORE_FILENAME gossip_store_filename
/* Derive the sibling paths from our per-process store path too, so the
 * .tmp/.compact/.corrupt files don't collide across parallel workers.
 * GOSSIP_STORE_FUZZ_OVERRIDE tells the production files to skip their own
 * (constant) definitions of these. */
#define GOSSIP_STORE_FUZZ_OVERRIDE
#define GOSSIP_STORE_TEMP_FILENAME    tal_strcat(tmpctx, GOSSIP_STORE_FILENAME, ".tmp")
#define GOSSIP_STORE_CORRUPT_FILENAME tal_strcat(tmpctx, GOSSIP_STORE_FILENAME, ".corrupt")
#define GOSSIP_STORE_COMPACT_FILENAME tal_strcat(tmpctx, GOSSIP_STORE_FILENAME, ".compact")

#define main gossipd_main
int gossipd_main(int argc, char *argv[]);
  #include "../../gossipd/gossip_store.c"
  #include "../../gossipd/gossipd.c"
  #include "../../gossipd/gossmap_manage.c"
  #include "../../gossipd/seeker.c"
#undef main

struct channel_info {
	struct short_channel_id scid;
	struct privkey from_pkey, to_pkey;
};

struct node_info {
	struct node_id id;
	struct privkey pkey;
};

/* Arrays to store gossip information. */
struct node_id *peer_ids;
struct node_info *nodes;
struct channel_info *channels;

static int connectd_fd;
static int master_fd;
static struct privkey funding_privkey;

/* Generate a unique, deterministic private key from an index. */
static struct privkey privkey_from_index(size_t index)
{
	struct privkey pkey;
	memset(&pkey, 0, sizeof(pkey));
	memcpy(pkey.secret.data, &index, sizeof(index));
	pkey.secret.data[sizeof(index)] = 1;
	return pkey;
}

static struct node_id node_id_from_privkey(struct privkey pkey)
{
	struct pubkey pk;
	struct node_id id;
	pubkey_from_privkey(&pkey, &pk);
	node_id_from_pubkey(&id, &pk);
	return id;
}

static struct daemon *new_daemon(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct daemon *daemon;
	const struct chainparams *chprms;
	u8 *msg;

	daemon = tal(ctx, struct daemon);
	daemon->developer = false;
	daemon->peers = new_htable(daemon, peer_node_id_map);
	daemon->deferred_txouts = tal_arr(daemon, struct short_channel_id, 0);
	daemon->current_blockheight = 0; /* i.e. unknown */
	timers_init(&daemon->timers, time_mono());
	daemon->master = daemon_conn_new(ctx, master_fd, NULL, NULL, daemon);

	size_t len = fromwire_u16(cursor, max);
	msg = tal_arr(ctx, u8, len);
	fromwire_u8_array(cursor, max, msg, len);

	if (!fromwire_gossipd_init(
		daemon, msg, &chprms, &daemon->our_features, &daemon->id,
		&daemon->autoconnect_seeker_peers, &daemon->compactd_helper,
		&daemon->dev_fast_gossip, &daemon->dev_fast_gossip_prune))
		return NULL;

	/* Too many seekers can cause out of memory errors. */
	if (daemon->autoconnect_seeker_peers > 10)
		daemon->autoconnect_seeker_peers = 10;

	daemon->gm = gossmap_manage_new(daemon, daemon);
	daemon->seeker = new_seeker(daemon);
	daemon->connectd = daemon_conn_new(ctx, connectd_fd, NULL, NULL, daemon);

	return daemon;
}

/* Create a signed channel_announcement and register the new channel. */
static u8 *create_channel_announcement(const tal_t *ctx, const u8 **cursor,
				       size_t *max)
{
	secp256k1_ecdsa_signature dummy_sig;
	struct pubkey funding_pubkey;
	struct privkey from_pkey, to_pkey;
	struct node_id from_id, to_id;
	struct short_channel_id scid;
	u8 *features;

	memset(&dummy_sig, 0, sizeof(dummy_sig));
	pubkey_from_privkey(&funding_privkey, &funding_pubkey);
	scid = fromwire_short_channel_id(cursor, max);

	from_pkey = privkey_from_index(fromwire_u64(cursor, max));
	from_id = node_id_from_privkey(from_pkey);
	tal_arr_expand(&nodes, ((struct node_info){from_id, from_pkey}));

	to_pkey = privkey_from_index(fromwire_u64(cursor, max));
	to_id = node_id_from_privkey(to_pkey);
	tal_arr_expand(&nodes, ((struct node_info){to_id, to_pkey}));

	tal_arr_expand(&channels, ((struct channel_info){scid, from_pkey, to_pkey}));

	size_t len = fromwire_u16(cursor, max);
	features = tal_arr(ctx, u8, len);
	fromwire_u8_array(cursor, max, features, len);

	u8 *chan_ann = towire_channel_announcement(
	    ctx, &dummy_sig, &dummy_sig, &dummy_sig, &dummy_sig, features,
	    &chainparams->genesis_blockhash, scid, &from_id, &to_id,
	    &funding_pubkey, &funding_pubkey);
	if (tal_count(chan_ann) > 65535) {
		return NULL;
	}

	/* Sign the message. */
	u8 compact[64];
	struct sha256_double hash;
	secp256k1_ecdsa_signature node_sig1, node_sig2, bitcoin_sig1, bitcoin_sig2;

	assert(tal_count(chan_ann) >= 258);
	sha256_double(&hash, chan_ann + 258, tal_count(chan_ann) - 258);

	sign_hash(&from_pkey, &hash, &node_sig1);
	sign_hash(&to_pkey, &hash, &node_sig2);
	sign_hash(&funding_privkey, &hash, &bitcoin_sig1);
	sign_hash(&funding_privkey, &hash, &bitcoin_sig2);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &node_sig1);
	memcpy(chan_ann + 2, compact, 64);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &node_sig2);
	memcpy(chan_ann + 66, compact, 64);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &bitcoin_sig1);
	memcpy(chan_ann + 130, compact, 64);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &bitcoin_sig2);
	memcpy(chan_ann + 194, compact, 64);

	return chan_ann;
}

/* Create a signed channel_update for a fuzzer-chosen existing channel. */
static u8 *create_channel_update(const tal_t *ctx, const u8 **cursor,
				 size_t *max)
{
	struct channel_info *channel_to_update;
	secp256k1_ecdsa_signature dummy_sig;
	u8 channel_flags, message_flags;
	u16 cltv_expiry_delta;
	u32 fee_base_msat, fee_proportional_millionths, timestamp;
	struct privkey node_pkey;
	struct amount_msat htlc_max_msat, htlc_min_msat;

	memset(&dummy_sig, 0, sizeof(dummy_sig));
	channel_to_update = &channels[fromwire_u64(cursor, max) % tal_count(channels)];
	node_pkey = (fromwire_u8(cursor, max) % 2)
			? channel_to_update->from_pkey
			: channel_to_update->to_pkey;

	channel_flags = fromwire_u8(cursor, max);

	if (fromwire_u8(cursor, max) % 4 != 0)
		timestamp = clock_time().ts.tv_sec - fromwire_u16(cursor, max);
	else
		timestamp = fromwire_u32(cursor, max);
	cltv_expiry_delta = fromwire_u16(cursor, max);
	fee_base_msat = fromwire_u32(cursor, max);
	fee_proportional_millionths = fromwire_u32(cursor, max);
	htlc_min_msat = fromwire_amount_msat(cursor, max);
	htlc_max_msat = fromwire_amount_msat(cursor, max);
	message_flags = fromwire_u8(cursor, max);

	u8 *chan_upd = towire_channel_update(
	    ctx, &dummy_sig, &chainparams->genesis_blockhash,
	    channel_to_update->scid, timestamp, message_flags, channel_flags,
	    cltv_expiry_delta, htlc_min_msat, fee_base_msat,
	    fee_proportional_millionths, htlc_max_msat);

	/* Sign the message. */
	u8 compact[64];
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;

	assert(tal_count(chan_upd) >= 66);
	sha256_double(&hash, chan_upd + 66, tal_count(chan_upd) - 66);

	sign_hash(&node_pkey, &hash, &sig);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &sig);
	memcpy(chan_upd + 2, compact, 64);

	return chan_upd;
}

/* Create a signed node_announcement for a fuzzer-chosen existing node. */
static u8 *create_node_announcement(const tal_t *ctx, const u8 **cursor,
				    size_t *max)
{
	secp256k1_ecdsa_signature dummy_sig;
	struct node_info *info;
	struct tlv_node_ann_tlvs *tlvs;
	u8 *features, *addresses;
	u32 timestamp;
	u8 rgb_color[3], alias[32];

	memset(&dummy_sig, 0, sizeof(dummy_sig));
	info = &nodes[fromwire_u64(cursor, max) % tal_count(nodes)];

	if (fromwire_u8(cursor, max) % 4 != 0)
		timestamp = clock_time().ts.tv_sec - fromwire_u16(cursor, max);
	else
		timestamp = fromwire_u32(cursor, max);

	size_t flen = fromwire_u16(cursor, max);
	features = tal_arr(ctx, u8, flen);
	fromwire_u8_array(cursor, max, features, flen);

	fromwire_u8_array(cursor, max, rgb_color, sizeof(rgb_color));
	fromwire_u8_array(cursor, max, alias, sizeof(alias));

	size_t addrlen = fromwire_u16(cursor, max);
	addresses = tal_arr(ctx, u8, addrlen);
	fromwire_u8_array(cursor, max, addresses, addrlen);

	if (fromwire_u8(cursor, max) % 2) {
		tlvs = fromwire_tlv_node_ann_tlvs(ctx, cursor, max);
	} else {
		tlvs = tlv_node_ann_tlvs_new(ctx);
	}

	u8 *node_ann = towire_node_announcement(ctx, &dummy_sig, features,
						timestamp, &info->id, rgb_color,
						alias, addresses, tlvs);
	if (tal_count(node_ann) > 65535) {
		return NULL;
	}

	/* Sign the message. */
	u8 compact[64];
	struct sha256_double hash;
	secp256k1_ecdsa_signature sig;

	assert(tal_count(node_ann) >= 66);
	sha256_double(&hash, node_ann + 66, tal_count(node_ann) - 66);

	sign_hash(&info->pkey, &hash, &sig);

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, &sig);
	memcpy(node_ann + 2, compact, 64);

	return node_ann;
}

/* Create a reply_channel_range message from fuzzer input. */
static u8 *create_reply_channel_range(const tal_t *ctx, const u8 **cursor,
				      size_t *max)
{
	u32 first_blocknum, number_of_blocks;
	u8 sync_complete, *encoded_scids;
	struct tlv_reply_channel_range_tlvs *tlvs;

	first_blocknum = fromwire_u32(cursor, max);
	number_of_blocks = fromwire_u32(cursor, max);
	sync_complete = fromwire_u8(cursor, max);

	size_t len = fromwire_u16(cursor, max);
	encoded_scids = tal_arr(ctx, u8, len);
	fromwire_u8_array(cursor, max, encoded_scids, len);

	if (fromwire_u8(cursor, max) % 2) {
		tlvs = fromwire_tlv_reply_channel_range_tlvs(ctx, cursor, max);
	} else {
		tlvs = tlv_reply_channel_range_tlvs_new(ctx);
	}

	u8 *reply = towire_reply_channel_range(
	    ctx, &chainparams->genesis_blockhash, first_blocknum,
	    number_of_blocks, sync_complete, encoded_scids, tlvs);
	if (tal_count(reply) > 65535) {
		return NULL;
	}

	return reply;
}

void init(int *argc, char ***argv)
{
	char *filename;
	int devnull;
	struct timeabs fixed_time;

	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");

	/* Gossipd writes to connectd/master fds, ignore SIGPIPE since
	 * nobody reads from the other end. */
	signal(SIGPIPE, SIG_IGN);

	close(tmpdir_mkstemp(NULL, "fuzz-gossipd-store.XXXXXX", &gossip_store_filename));
	connectd_fd = tmpdir_mkstemp(NULL, "fuzz-gossipd-connectd.XXXXXX", &filename);
	master_fd = tmpdir_mkstemp(NULL, "fuzz-gossipd-master.XXXXXX", &filename);
	devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
	chainparams = chainparams_for_network("bitcoin");
	memset(&funding_privkey, 'F', sizeof(funding_privkey));

	fixed_time.ts.tv_sec = 1550513768;
	fixed_time.ts.tv_nsec = 0;
	dev_override_clock_time(fixed_time);
	fuzz_allow_siphash_seed = true;
}

void run(const uint8_t *data, size_t size)
{
	struct daemon *daemon = new_daemon(tmpctx, &data, &size);
	if (!daemon)
		goto cleanup;

	peer_ids = tal_arr(tmpctx, struct node_id, 0);
	nodes = tal_arr(tmpctx, struct node_info, 0);
	channels = tal_arr(tmpctx, struct channel_info, 0);

	while (size > sizeof(u8)) {

		u8 *msg = tal_arr(tmpctx, u8, 0);

		int op = fromwire_u8(&data, &size) % 10;
		switch (op) {
		case 0: /* WIRE_GOSSIPD_NEW_PEER */
		{
			struct privkey node_pkey = privkey_from_index(tal_count(peer_ids));
			struct node_id id = node_id_from_privkey(node_pkey);
			tal_arr_expand(&peer_ids, id);

			bool gossip_queries_feature = fromwire_u8(&data, &size) % 2;
			msg = towire_gossipd_new_peer(tmpctx, &id, gossip_queries_feature);
			connectd_new_peer(daemon, msg);
			break;
		}
		case 1: /* WIRE_GOSSIPD_PEER_GONE */
		{
			if (tal_count(peer_ids) == 0)
				break;

			size_t idx = fromwire_u64(&data, &size) % tal_count(peer_ids);
			struct node_id id_to_del = peer_ids[idx];
			tal_arr_remove(&peer_ids, idx);

			msg = towire_gossipd_peer_gone(tmpctx, &id_to_del);
			connectd_peer_gone(daemon, msg);
			break;
		}
		case 2: /* WIRE_CHANNEL_ANNOUNCEMENT */
		{
			if (tal_count(peer_ids) == 0)
				break;

			struct node_id peer = peer_ids[fromwire_u64(&data, &size) % tal_count(peer_ids)];
			u8 *chan_ann = create_channel_announcement(tmpctx, &data, &size);

			if (chan_ann) {
				msg = towire_gossipd_recv_gossip(tmpctx, &peer, chan_ann);
				handle_recv_gossip(daemon, msg);
			}
			break;
		}
		case 3: /* WIRE_CHANNEL_UPDATE */
		{
			if (tal_count(peer_ids) == 0 || tal_count(channels) == 0)
				break;

			struct node_id peer = peer_ids[fromwire_u64(&data, &size) % tal_count(peer_ids)];
			u8 *chan_upd = create_channel_update(tmpctx, &data, &size);

			msg = towire_gossipd_recv_gossip(tmpctx, &peer, chan_upd);
			handle_recv_gossip(daemon, msg);
			break;
		}
		case 4: /* WIRE_NODE_ANNOUNCEMENT */
		{
			if (tal_count(peer_ids) == 0 || tal_count(nodes) == 0)
				break;

			struct node_id peer = peer_ids[fromwire_u64(&data, &size) % tal_count(peer_ids)];
			u8 *node_ann = create_node_announcement(tmpctx, &data, &size);

			if (node_ann) {
				msg = towire_gossipd_recv_gossip(tmpctx, &peer, node_ann);
				handle_recv_gossip(daemon, msg);
			}
			break;
		}
		case 5: /* WIRE_GOSSIPD_NEW_BLOCKHEIGHT */
		{
			u32 new_bh = fromwire_u32(&data, &size);
			u32 blockheight = new_bh > daemon->current_blockheight ? new_bh : daemon->current_blockheight;

			msg = towire_gossipd_new_blockheight(tmpctx, blockheight);
			new_blockheight(daemon, msg);
			break;
		}
		case 6: /* WIRE_GOSSIPD_GET_TXOUT_REPLY */
		{
			if (tal_count(channels) == 0)
				break;

			struct channel_info *ch = &channels[fromwire_u64(&data, &size) % tal_count(channels)];
			struct amount_sat amt;
			u8 *script;

			if (fromwire_u8(&data, &size) % 2) {
				/* Valid UTXO. */
				struct pubkey fpk;
				amt = AMOUNT_SAT(10000000);
				pubkey_from_privkey(&funding_privkey, &fpk);
				script = scriptpubkey_p2wsh(tmpctx, bitcoin_redeem_2of2(tmpctx, &fpk, &fpk));
			} else {
				/* Spent UTXO. */
				amt = AMOUNT_SAT(0);
				script = NULL;
			}

			u8 *reply = towire_gossipd_get_txout_reply(tmpctx, ch->scid, amt, script);
			gossmap_manage_handle_get_txout_reply(daemon->gm, reply);
			break;
		}
		case 7: /* Drive seeker state machine */
		{
			/* Advance the seeker explicitly instead of relying
			 * on its timer, so it can send gossip queries
			 * and we can process replies. */
			seeker_check(daemon->seeker);
			break;
		}
		case 8: /* WIRE_REPLY_CHANNEL_RANGE */
		{
			if (tal_count(peer_ids) == 0)
				break;

			struct node_id peer_id = peer_ids[fromwire_u64(&data, &size) % tal_count(peer_ids)];
			u8 *reply = create_reply_channel_range(tmpctx, &data, &size);

			if (reply) {
				msg = towire_gossipd_recv_gossip(tmpctx, &peer_id, reply);
				handle_recv_gossip(daemon, msg);
			}
			break;
		}
		case 9: /* WIRE_REPLY_SHORT_CHANNEL_IDS_END */
		{
			if (tal_count(peer_ids) == 0)
				break;

			struct node_id peer_id = peer_ids[fromwire_u64(&data, &size) % tal_count(peer_ids)];
			u8 complete = fromwire_u8(&data, &size);
			u8 *reply = towire_reply_short_channel_ids_end(tmpctx, &chainparams->genesis_blockhash, complete);

			msg = towire_gossipd_recv_gossip(tmpctx, &peer_id, reply);
			handle_recv_gossip(daemon, msg);
			break;
		}
		}
	}

cleanup:
	if (daemon) {
		uintmap_clear(&daemon->gm->pending_ann_map.map);
		uintmap_clear(&daemon->gm->early_ann_map.map);
		uintmap_clear(&daemon->gm->txf->failures[0]);
		uintmap_clear(&daemon->gm->txf->failures[1]);
		uintmap_clear(&daemon->seeker->unknown_scids);
		uintmap_clear(&daemon->seeker->stale_scids);
	}
	clean_tmpctx();
}
