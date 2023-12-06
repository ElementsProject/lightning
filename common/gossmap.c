#include "config.h"
#include <assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/err/err.h>
#include <ccan/htable/htable_type.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/gossip_store.h>
#include <common/gossmap.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wire/peer_wire.h>

bool gossmap_public_only;

/* We need this global to decode indexes for hash functions */
static struct gossmap *map;

/* This makes an htable of indices into our array. */
static struct short_channel_id chanidx_id(const ptrint_t *pidx);
static bool chanidx_eq_id(const ptrint_t *pidx,
			  struct short_channel_id scid)
{
	struct short_channel_id pidxid = chanidx_id(pidx);
	return short_channel_id_eq(&pidxid, &scid);
}
static size_t scid_hash(const struct short_channel_id scid)
{
	return siphash24(siphash_seed(), &scid, sizeof(scid));
}
HTABLE_DEFINE_TYPE(ptrint_t, chanidx_id, scid_hash, chanidx_eq_id,
		   chanidx_htable);

static struct node_id nodeidx_id(const ptrint_t *pidx);
static bool nodeidx_eq_id(const ptrint_t *pidx, const struct node_id id)
{
	struct node_id pidxid = nodeidx_id(pidx);
	return node_id_eq(&pidxid, &id);
}
static size_t nodeid_hash(const struct node_id id)
{
	return siphash24(siphash_seed(), &id, PUBKEY_CMPR_LEN);
}
HTABLE_DEFINE_TYPE(ptrint_t, nodeidx_id, nodeid_hash, nodeidx_eq_id,
		   nodeidx_htable);

struct gossmap {
	/* The file descriptor and filename to monitor */
	int fd;
	const char *fname;

	/* The memory map of the file: u8 for arithmetic portability */
	u8 *mmap;
	/* map_end is where we read to so far, map_size is total size */
	size_t map_end, map_size;

	/* Map of node id -> node */
	struct nodeidx_htable *nodes;

	/* Map of short_channel_id id -> channel */
	struct chanidx_htable *channels;

	/* Array of nodes, so we can use simple index. */
	struct gossmap_node *node_arr;
	/* This is tal_count(node_arr), which we call very often in assert() */
	size_t num_node_arr;

	/* Array of chans, so we can use simple index */
	struct gossmap_chan *chan_arr;
	/* This is tal_count(chan_arr), which we call very often in assert() */
	size_t num_chan_arr;

	/* Linked list of freed ones, if any. */
	u32 freed_nodes, freed_chans;

	/* local messages, if any. */
	const u8 *local;
};

/* Accessors for the gossmap */
static void map_copy(const struct gossmap *map, size_t offset,
		     void *dst, size_t len)
{
	if (offset >= map->map_size) {
		size_t localoff = offset - map->map_size;
		assert(localoff + len <= tal_bytelen(map->local));
		memcpy(dst, map->local + localoff, len);
	} else {
		assert(offset + len <= map->map_size);
		if (map->mmap)
			memcpy(dst, map->mmap + offset, len);
		else {
			/* Yeah, we'll crash on I/O errors. */
			if (pread(map->fd, dst, len, offset) != len)
				abort();
		}
	}
}

static u8 map_u8(const struct gossmap *map, size_t offset)
{
	u8 u8;
	map_copy(map, offset, &u8, sizeof(u8));
	return u8;
}

static u16 map_be16(const struct gossmap *map, size_t offset)
{
	be16 be16;
	map_copy(map, offset, &be16, sizeof(be16));
	return be16_to_cpu(be16);
}

static u32 map_be32(const struct gossmap *map, size_t offset)
{
	be32 be32;
	map_copy(map, offset, &be32, sizeof(be32));
	return be32_to_cpu(be32);
}

static u64 map_be64(const struct gossmap *map, size_t offset)
{
	be64 be64;
	map_copy(map, offset, &be64, sizeof(be64));
	return be64_to_cpu(be64);
}

static void map_nodeid(const struct gossmap *map, size_t offset,
		       struct node_id *id)
{
	map_copy(map, offset, id, sizeof(*id));
}

/* Returns optional or compulsory feature if set, otherwise -1 */
static int map_feature_test(const struct gossmap *map,
			    int compulsory_bit,
			    size_t offset, size_t len)
{
	size_t bytenum = compulsory_bit / 8;
	u8 bits;

	assert(COMPULSORY_FEATURE(compulsory_bit) == compulsory_bit);
	if (bytenum >= len)
		return -1;

	/* Note reversed! */
	bits = map_u8(map, offset + len - 1 - bytenum);
	if (bits & (1 << (compulsory_bit % 8)))
		return compulsory_bit;
	if (bits & (1 << (OPTIONAL_FEATURE(compulsory_bit) % 8)))
		return OPTIONAL_FEATURE(compulsory_bit);
	return -1;
}

/* These values can change across calls to gossmap_check. */
u32 gossmap_max_node_idx(const struct gossmap *map)
{
	assert(tal_count(map->node_arr) == map->num_node_arr);
	return map->num_node_arr;
}

u32 gossmap_max_chan_idx(const struct gossmap *map)
{
	assert(tal_count(map->chan_arr) == map->num_chan_arr);
	return map->num_chan_arr;
}

/* Each channel has a unique (low) index. */
u32 gossmap_node_idx(const struct gossmap *map, const struct gossmap_node *node)
{
	assert(node - map->node_arr < map->num_node_arr);
	return node - map->node_arr;
}

u32 gossmap_chan_idx(const struct gossmap *map, const struct gossmap_chan *chan)
{
	assert(chan - map->chan_arr < map->num_chan_arr);
	return chan - map->chan_arr;
}

struct gossmap_node *gossmap_node_byidx(const struct gossmap *map, u32 idx)
{
	assert(idx < gossmap_max_node_idx(map));
	if (map->node_arr[idx].chan_idxs == NULL)
		return NULL;
	return &map->node_arr[idx];
}

struct gossmap_chan *gossmap_chan_byidx(const struct gossmap *map, u32 idx)
{
	assert(idx < gossmap_max_chan_idx(map));

	if (map->chan_arr[idx].plus_scid_off == 0)
		return NULL;
	return &map->chan_arr[idx];
}

/* htable can't handle NULL or 1 values, so we add 2 */
static struct gossmap_chan *ptrint2chan(const ptrint_t *pidx)
{
	return map->chan_arr + ptr2int(pidx) - 2;
}

static ptrint_t *chan2ptrint(const struct gossmap_chan *chan)
{
	return int2ptr(chan - map->chan_arr + 2);
}

static struct gossmap_node *ptrint2node(const ptrint_t *pidx)
{
	return map->node_arr + ptr2int(pidx) - 2;
}

static ptrint_t *node2ptrint(const struct gossmap_node *node)
{
	return int2ptr(node - map->node_arr + 2);
}

static struct short_channel_id chanidx_id(const ptrint_t *pidx)
{
	return gossmap_chan_scid(map, ptrint2chan(pidx));
}

static struct node_id nodeidx_id(const ptrint_t *pidx)
{
	struct node_id id;
	gossmap_node_get_id(map, ptrint2node(pidx), &id);
	return id;
}

struct gossmap_node *gossmap_find_node(const struct gossmap *map,
				       const struct node_id *id)
{
	ptrint_t *pi = nodeidx_htable_get(map->nodes, *id);
	if (pi)
		return ptrint2node(pi);
	return NULL;
}

struct gossmap_chan *gossmap_find_chan(const struct gossmap *map,
				       const struct short_channel_id *scid)
{
	ptrint_t *pi = chanidx_htable_get(map->channels, *scid);
	if (pi)
		return ptrint2chan(pi);
	return NULL;
}

static u32 init_node_arr(struct gossmap_node *node_arr, size_t start)
{
	size_t i;
	for (i = start; i < tal_count(node_arr) - 1; i++) {
		node_arr[i].nann_off = i + 1;
		node_arr[i].chan_idxs = NULL;
	}
	node_arr[i].nann_off = UINT_MAX;
	node_arr[i].chan_idxs = NULL;

	return start;
}

/* Freelist links through node_off of unused entries. */
static struct gossmap_node *next_free_node(struct gossmap *map)
{
	size_t f;

	if (map->freed_nodes == UINT_MAX) {
		/* Double in size, add second half to free list */
		size_t n = tal_count(map->node_arr);
		map->num_node_arr *= 2;
		tal_resize(&map->node_arr, n * 2);
		map->freed_nodes = init_node_arr(map->node_arr, n);
	}

	f = map->freed_nodes;
	map->freed_nodes = map->node_arr[f].nann_off;
	return &map->node_arr[f];
}

static u32 new_node(struct gossmap *map)
{
	struct gossmap_node *node = next_free_node(map);

	assert(node->chan_idxs == NULL);
	node->nann_off = 0;
	node->num_chans = 0;

	return gossmap_node_idx(map, node);
}

static void remove_node(struct gossmap *map, struct gossmap_node *node)
{
	u32 nodeidx = gossmap_node_idx(map, node);
	if (!nodeidx_htable_del(map->nodes, node2ptrint(node)))
		abort();
	node->nann_off = map->freed_nodes;
	free(node->chan_idxs);
	node->chan_idxs = NULL;
	node->num_chans = 0;
	map->freed_nodes = nodeidx;
}

static void node_add_channel(struct gossmap_node *node, u32 chanidx)
{
	node->num_chans++;
	node->chan_idxs = realloc(node->chan_idxs,
				  node->num_chans * sizeof(*node->chan_idxs));
	node->chan_idxs[node->num_chans-1] = chanidx;
}

static u32 init_chan_arr(struct gossmap_chan *chan_arr, size_t start)
{
	size_t i;
	for (i = start; i < tal_count(chan_arr) - 1; i++) {
		chan_arr[i].cann_off = i + 1;
		chan_arr[i].plus_scid_off = 0;
		/* We don't need to initialize this, *but* on some platforms
		 * (ppc, arm64) valgrind complains: this is a bitfield shared
		 * with plus_scid_off */
		chan_arr[i].private = false;
	}
	chan_arr[i].cann_off = UINT_MAX;
	chan_arr[i].plus_scid_off = 0;
	chan_arr[i].private = false;
	return start;
}

/* Freelist links through scid of unused entries. */
static struct gossmap_chan *next_free_chan(struct gossmap *map)
{
	size_t f;

	if (map->freed_chans == UINT_MAX) {
		/* Double in size, add second half to free list */
		size_t n = tal_count(map->chan_arr);
		map->num_chan_arr *= 2;
		tal_resize(&map->chan_arr, n * 2);
		map->freed_chans = init_chan_arr(map->chan_arr, n);
	}

	f = map->freed_chans;
	map->freed_chans = map->chan_arr[f].cann_off;
	return &map->chan_arr[f];
}

static struct gossmap_chan *new_channel(struct gossmap *map,
					u32 cannounce_off,
					u32 plus_scid_off,
					bool private,
					u32 n1idx, u32 n2idx)
{
	struct gossmap_chan *chan = next_free_chan(map);

	chan->cann_off = cannounce_off;
	chan->private = private;
	chan->plus_scid_off = plus_scid_off;
	chan->cupdate_off[0] = chan->cupdate_off[1] = 0;
	memset(chan->half, 0, sizeof(chan->half));
	chan->half[0].nodeidx = n1idx;
	chan->half[1].nodeidx = n2idx;
	node_add_channel(map->node_arr + n1idx, gossmap_chan_idx(map, chan));
	node_add_channel(map->node_arr + n2idx, gossmap_chan_idx(map, chan));
	chanidx_htable_add(map->channels, chan2ptrint(chan));

	return chan;
}

static void remove_chan_from_node(struct gossmap *map,
				  struct gossmap_node *node,
				  u32 chanidx)
{
	size_t i;

	if (node->num_chans == 1) {
		remove_node(map, node);
		return;
	}
	for (i = 0; node->chan_idxs[i] != chanidx; i++)
		assert(i < node->num_chans);

	memmove(node->chan_idxs + i,
		node->chan_idxs + i + 1,
		sizeof(node->chan_idxs[0]) * (node->num_chans - i - 1));
	node->num_chans--;
}

void gossmap_remove_chan(struct gossmap *map, struct gossmap_chan *chan)
{
	u32 chanidx = gossmap_chan_idx(map, chan);
	if (!chanidx_htable_del(map->channels, chan2ptrint(chan)))
		abort();
	remove_chan_from_node(map, gossmap_nth_node(map, chan, 0), chanidx);
	remove_chan_from_node(map, gossmap_nth_node(map, chan, 1), chanidx);
	chan->cann_off = map->freed_chans;
	chan->plus_scid_off = 0;
	map->freed_chans = chanidx;
}

void gossmap_remove_node(struct gossmap *map, struct gossmap_node *node)
{
	while (node->num_chans != 0)
		gossmap_remove_chan(map, gossmap_nth_chan(map, node, 0, NULL));
}

/* BOLT #7:
 * 1. type: 256 (`channel_announcement`)
 * 2. data:
 *     * [`signature`:`node_signature_1`]
 *     * [`signature`:`node_signature_2`]
 *     * [`signature`:`bitcoin_signature_1`]
 *     * [`signature`:`bitcoin_signature_2`]
 *     * [`u16`:`len`]
 *     * [`len*byte`:`features`]
 *     * [`chain_hash`:`chain_hash`]
 *     * [`short_channel_id`:`short_channel_id`]
 *     * [`point`:`node_id_1`]
 *     * [`point`:`node_id_2`]
 */
static struct gossmap_chan *add_channel(struct gossmap *map,
					size_t cannounce_off,
					bool private)
{
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + (64 + 64 + 64 + 64);
	size_t feature_len;
	size_t plus_scid_off;
	struct short_channel_id scid;
	struct node_id node_id[2];
	struct gossmap_node *n[2];
	struct gossmap_chan *chan;
	u32 nidx[2];

	feature_len = map_be16(map, cannounce_off + feature_len_off);
	plus_scid_off = feature_len_off + 2 + feature_len + 32;

	map_nodeid(map, cannounce_off + plus_scid_off + 8, &node_id[0]);
	map_nodeid(map, cannounce_off + plus_scid_off + 8 + PUBKEY_CMPR_LEN, &node_id[1]);

	/* We can have a channel upgrade from private->public, but
	 * that's the only time we get duplicates */
	scid.u64 = map_be64(map, cannounce_off + plus_scid_off);
	chan = gossmap_find_chan(map, &scid);
	if (chan)
		gossmap_remove_chan(map, chan);

	/* We carefully map pointers to indexes, since new_node can move them! */
	n[0] = gossmap_find_node(map, &node_id[0]);
	if (n[0])
		nidx[0] = gossmap_node_idx(map, n[0]);
	else
		nidx[0] = new_node(map);

	n[1] = gossmap_find_node(map, &node_id[1]);
	if (n[1])
		nidx[1] = gossmap_node_idx(map, n[1]);
	else
		nidx[1] = new_node(map);

	chan = new_channel(map, cannounce_off, plus_scid_off, private,
			   nidx[0], nidx[1]);

	/* Now we have a channel, we can add nodes to htable */
	if (!n[0])
		nodeidx_htable_add(map->nodes,
				   node2ptrint(map->node_arr + nidx[0]));
	if (!n[1])
		nodeidx_htable_add(map->nodes,
				   node2ptrint(map->node_arr + nidx[1]));

	return chan;
}

/* BOLT #7:
 * 1. type: 258 (`channel_update`)
 * 2. data:
 *     * [`signature`:`signature`]
 *     * [`chain_hash`:`chain_hash`]
 *     * [`short_channel_id`:`short_channel_id`]
 *     * [`u32`:`timestamp`]
 *     * [`byte`:`message_flags`]
 *     * [`byte`:`channel_flags`]
 *     * [`u16`:`cltv_expiry_delta`]
 *     * [`u64`:`htlc_minimum_msat`]
 *     * [`u32`:`fee_base_msat`]
 *     * [`u32`:`fee_proportional_millionths`]
 *     * [`u64`:`htlc_maximum_msat`]
 */
static bool update_channel(struct gossmap *map, size_t cupdate_off)
{
	/* Note that first two bytes are message type */
	const size_t scid_off = cupdate_off + 2 + (64 + 32);
	const size_t message_flags_off = scid_off + 8 + 4;
	const size_t channel_flags_off = message_flags_off + 1;
	const size_t cltv_expiry_delta_off = channel_flags_off + 1;
	const size_t htlc_minimum_off = cltv_expiry_delta_off + 2;
	const size_t fee_base_off = htlc_minimum_off + 8;
	const size_t fee_prop_off = fee_base_off + 4;
	const size_t htlc_maximum_off = fee_prop_off + 4;
	struct short_channel_id scid;
	struct gossmap_chan *chan;
	struct half_chan hc;
	u8 chanflags;
	bool dumb_values;

	scid.u64 = map_be64(map, scid_off);
	chan = gossmap_find_chan(map, &scid);
	/* This can happen if channel gets deleted! */
	if (!chan)
		return false;

	/* We round this *down*, since too-low min is more conservative */
	hc.htlc_min = u64_to_fp16(map_be64(map, htlc_minimum_off), false);
	hc.htlc_max = u64_to_fp16(map_be64(map, htlc_maximum_off), true);

	chanflags = map_u8(map, channel_flags_off);
	hc.enabled = !(chanflags & 2);
	hc.base_fee = map_be32(map, fee_base_off);
	hc.proportional_fee = map_be32(map, fee_prop_off);
	hc.delay = map_be16(map, cltv_expiry_delta_off);

	/* Check they fit: we turn off if not. */
	if (hc.base_fee != map_be32(map, fee_base_off)
	    || hc.proportional_fee != map_be32(map, fee_prop_off)
	    || hc.delay != map_be16(map, cltv_expiry_delta_off)) {
		dumb_values = true;
		hc.htlc_max = 0;
		hc.enabled = false;
	} else
		dumb_values = false;

	/* Preserve this */
	hc.nodeidx = chan->half[chanflags & 1].nodeidx;
	chan->half[chanflags & 1] = hc;
	chan->cupdate_off[chanflags & 1] = cupdate_off;

	return !dumb_values;
}

static void remove_channel_by_deletemsg(struct gossmap *map, size_t del_off)
{
	struct short_channel_id scid;
	struct gossmap_chan *chan;

	/* They can delete things we don't know about, since they also
	 * get their length marked with the deleted bit */
	/* Note that first two bytes are message type */
	scid.u64 = map_be64(map, del_off + 2);
	chan = gossmap_find_chan(map, &scid);
	if (!chan)
		return;

	gossmap_remove_chan(map, chan);
}

struct short_channel_id gossmap_chan_scid(const struct gossmap *map,
					  const struct gossmap_chan *c)
{
	struct short_channel_id scid;
	scid.u64 = map_be64(map, c->cann_off + c->plus_scid_off);

	return scid;
}

/* BOLT #7:
 * 1. type: 257 (`node_announcement`)
 * 2. data:
 *    * [`signature`:`signature`]
 *    * [`u16`:`flen`]
 *    * [`flen*byte`:`features`]
 *    * [`u32`:`timestamp`]
 *    * [`point`:`node_id`]
 *    * [`3*byte`:`rgb_color`]
 *    * [`32*byte`:`alias`]
 *    * [`u16`:`addrlen`]
 *    * [`addrlen*byte`:`addresses`]
 */
static void node_announcement(struct gossmap *map, size_t nann_off)
{
	const size_t feature_len_off = 2 + 64;
	size_t feature_len;
	struct gossmap_node *n;
	struct node_id id;

	feature_len = map_be16(map, nann_off + feature_len_off);
	map_nodeid(map, nann_off + feature_len_off + 2 + feature_len + 4, &id);
	if ((n = gossmap_find_node(map, &id)))
		n->nann_off = nann_off;
}

static void reopen_store(struct gossmap *map, size_t ended_off)
{
	int fd = open(map->fname, O_RDONLY);

	if (fd < 0)
		err(1, "Failed to reopen %s", map->fname);

	/* This tells us the equivalent offset in new map */
	map->map_end = map_be64(map, ended_off + 2);

	close(map->fd);
	map->fd = fd;
	gossmap_refresh(map, NULL);
}

static bool map_catchup(struct gossmap *map, size_t *num_rejected)
{
	size_t reclen;
	bool changed = false;
	size_t num_bad = 0;

	for (; map->map_end + sizeof(struct gossip_hdr) < map->map_size;
	     map->map_end += reclen) {
		struct gossip_hdr ghdr;
		size_t off;
		u16 type, flags;

		map_copy(map, map->map_end, &ghdr, sizeof(ghdr));
		reclen = be16_to_cpu(ghdr.len) + sizeof(ghdr);

		flags = be16_to_cpu(ghdr.flags);
		if (flags & GOSSIP_STORE_DELETED_BIT)
			continue;

		if (flags & GOSSIP_STORE_ZOMBIE_BIT)
			continue;

		/* Partial write, this can happen. */
		if (map->map_end + reclen > map->map_size)
			break;

		off = map->map_end + sizeof(ghdr);
		type = map_be16(map, off);
		if (type == WIRE_CHANNEL_ANNOUNCEMENT)
			add_channel(map, off, false);
		else if (type == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL && !gossmap_public_only)
			add_channel(map, off + 2 + 8 + 2, true);
		else if (type == WIRE_CHANNEL_UPDATE)
			num_bad += !update_channel(map, off);
		else if (type == WIRE_GOSSIP_STORE_PRIVATE_UPDATE && !gossmap_public_only)
			num_bad += !update_channel(map, off + 2 + 2);
		else if (type == WIRE_GOSSIP_STORE_DELETE_CHAN)
			remove_channel_by_deletemsg(map, off);
		else if (type == WIRE_NODE_ANNOUNCEMENT)
			node_announcement(map, off);
		else if (type == WIRE_GOSSIP_STORE_ENDED)
			reopen_store(map, off);
		else
			continue;

		changed = true;
	}

	if (num_rejected)
		*num_rejected = num_bad;
	return changed;
}

static bool load_gossip_store(struct gossmap *map, size_t *num_rejected)
{
	map->fd = open(map->fname, O_RDONLY);
	if (map->fd < 0)
		return false;

	map->map_size = lseek(map->fd, 0, SEEK_END);
	map->local = NULL;
	/* If this fails, we fall back to read */
	map->mmap = mmap(NULL, map->map_size, PROT_READ, MAP_SHARED, map->fd, 0);
	if (map->mmap == MAP_FAILED)
		map->mmap = NULL;

	/* We only support major version 0 */
	if (GOSSIP_STORE_MAJOR_VERSION(map_u8(map, 0)) != 0) {
		close(map->fd);
		if (map->mmap)
			munmap(map->mmap, map->map_size);
		errno = EINVAL;
		return false;
	}

	/* Since channel_announcement is ~430 bytes, and channel_update is 136,
	 * node_announcement is 144, and current topology has 35000 channels
	 * and 10000 nodes, let's assume each channel gets about 750 bytes.
	 *
	 * We halve this, since often some records are deleted. */
	map->channels = tal(map, struct chanidx_htable);
	chanidx_htable_init_sized(map->channels, map->map_size / 750 / 2);
	map->nodes = tal(map, struct nodeidx_htable);
	nodeidx_htable_init_sized(map->nodes, map->map_size / 2500 / 2);

	map->num_chan_arr = map->map_size / 750 / 2 + 1;
	map->chan_arr = tal_arr(map, struct gossmap_chan, map->num_chan_arr);
	map->freed_chans = init_chan_arr(map->chan_arr, 0);
	map->num_node_arr = map->map_size / 2500 / 2 + 1;
	map->node_arr = tal_arr(map, struct gossmap_node, map->num_node_arr);
	map->freed_nodes = init_node_arr(map->node_arr, 0);

	map->map_end = 1;
	map_catchup(map, num_rejected);
	return true;
}

static void destroy_map(struct gossmap *map)
{
	if (map->mmap)
		munmap(map->mmap, map->map_size);

	for (size_t i = 0; i < tal_count(map->node_arr); i++)
		free(map->node_arr[i].chan_idxs);
}

/* Local modifications.  We only expect a few, so we use a simple
 * array. */
struct localmod {
	struct short_channel_id scid;
	/* If this is an entirely-local channel, here's its offset.
	 * Otherwise, 0xFFFFFFFF. */
	u32 local_off;

	/* Are updates in either direction set? */
	bool updates_set[2];
	/* hc[n] defined if updates_set[n]. */
	struct half_chan hc[2];
	/* orig[n] defined if updates_set[n] and local_off == 0xFFFFFFFF */
	struct half_chan orig[2];

	/* Original update offsets */
	u32 orig_cupdate_off[2];
};

struct gossmap_localmods {
	struct localmod *mods;
	/* This is the local array to be used by the gossmap */
	u8 *local;
};

struct gossmap_localmods *gossmap_localmods_new(const tal_t *ctx)
{
	struct gossmap_localmods *localmods;

	localmods = tal(ctx, struct gossmap_localmods);
	localmods->mods = tal_arr(localmods, struct localmod, 0);
	localmods->local = tal_arr(localmods, u8, 0);

	return localmods;
}

/* Create space at end of local map, return offset it was added at. */
static size_t insert_local_space(struct gossmap_localmods *localmods,
				 size_t msglen)
{
	size_t oldlen = tal_bytelen(localmods->local);

	tal_resize(&localmods->local, oldlen + msglen);
	return oldlen;
}

static struct localmod *find_localmod(struct gossmap_localmods *localmods,
				      const struct short_channel_id *scid)
{
	for (size_t i = 0; i < tal_count(localmods->mods); i++)
		if (short_channel_id_eq(&localmods->mods[i].scid, scid))
			return &localmods->mods[i];
	return NULL;
}

bool gossmap_local_addchan(struct gossmap_localmods *localmods,
			   const struct node_id *n1,
			   const struct node_id *n2,
			   const struct short_channel_id *scid,
			   const u8 *features)
{
	be16 be16;
	be64 be64;
	size_t off;
	struct localmod mod;

	/* Don't create duplicate channels. */
	if (find_localmod(localmods, scid))
		return false;

	/* BOLT #7:
	 *
	 * - MUST set `node_id_1` and `node_id_2` to the public keys
	 *   of the two nodes operating the channel, such that
	 *   `node_id_1` is the lexicographically-lesser of the two
	 *   compressed keys sorted in ascending lexicographic order.
	 */
	if (node_id_cmp(n1, n2) > 0)
		return gossmap_local_addchan(localmods, n2, n1, scid, features);

	mod.scid = *scid;
	mod.updates_set[0] = mod.updates_set[1] = false;

	/* We create fake local channel_announcement. */
	off = insert_local_space(localmods,
				 2 + 64 * 4 + 2 + tal_bytelen(features)
				 + 32 + 8 + 33 + 33);
	mod.local_off = off;

	/* Set type to be kosher. */
	be16 = CPU_TO_BE16(WIRE_CHANNEL_ANNOUNCEMENT);
	memcpy(localmods->local + off, &be16, sizeof(be16));
	off += sizeof(be16);

	/* Skip sigs */
	off += 64 * 4;

	/* Set length and features */
	be16 = cpu_to_be16(tal_bytelen(features));
	memcpy(localmods->local + off, &be16, sizeof(be16));
	off += sizeof(be16);
	/* Damn you, C committee! */
	if (features)
		memcpy(localmods->local + off, features, tal_bytelen(features));
	off += tal_bytelen(features);

	/* Skip chain_hash */
	off += 32;

	/* Set scid */
	be64 = be64_to_cpu(scid->u64);
	memcpy(localmods->local + off, &be64, sizeof(be64));
	off += sizeof(be64);

	/* set node_ids */
	memcpy(localmods->local + off, n1->k, sizeof(n1->k));
	off += sizeof(n1->k);
	memcpy(localmods->local + off, n2->k, sizeof(n2->k));
	off += sizeof(n2->k);

	assert(off == tal_bytelen(localmods->local));

	tal_arr_expand(&localmods->mods, mod);
	return true;
};

/* Insert a local-only channel_update. */
bool gossmap_local_updatechan(struct gossmap_localmods *localmods,
			      const struct short_channel_id *scid,
			      struct amount_msat htlc_min,
			      struct amount_msat htlc_max,
			      u32 base_fee,
			      u32 proportional_fee,
			      u16 delay,
			      bool enabled,
			      int dir)
{
	struct localmod *mod;

	mod = find_localmod(localmods, scid);
	if (!mod) {
		/* Create new reference to (presumably) existing channel. */
		size_t nmods = tal_count(localmods->mods);

		tal_resize(&localmods->mods, nmods + 1);
		mod = &localmods->mods[nmods];
		mod->scid = *scid;
		mod->updates_set[0] = mod->updates_set[1] = false;
		mod->local_off = 0xFFFFFFFF;
	}

	assert(dir == 0 || dir == 1);
	mod->updates_set[dir] = true;
	mod->hc[dir].enabled = enabled;
	/* node_idx needs to be set once we're in the gossmap. */
	mod->hc[dir].htlc_min
		= u64_to_fp16(htlc_min.millisatoshis, /* Raw: to fp16 */
			      false);
	mod->hc[dir].htlc_max
		= u64_to_fp16(htlc_max.millisatoshis, /* Raw: to fp16 */
			      true);
	mod->hc[dir].base_fee = base_fee;
	mod->hc[dir].proportional_fee = proportional_fee;
	mod->hc[dir].delay = delay;

	/* Check they fit */
	if (mod->hc[dir].base_fee != base_fee
	    || mod->hc[dir].proportional_fee != proportional_fee
	    || mod->hc[dir].delay != delay)
		return false;
	return true;
}

/* Apply localmods to this map */
void gossmap_apply_localmods(struct gossmap *map,
			     struct gossmap_localmods *localmods)
{
	size_t n = tal_count(localmods->mods);

	assert(!map->local);
	map->local = localmods->local;

	for (size_t i = 0; i < n; i++) {
		struct localmod *mod = &localmods->mods[i];
		struct gossmap_chan *chan;

		/* Find gossmap entry which this applies to. */
		chan = gossmap_find_chan(map, &mod->scid);
		/* If it doesn't exist, are we supposed to create a local one? */
		if (!chan) {
			if (mod->local_off == 0xFFFFFFFF)
				continue;

			/* Create new channel, pointing into local. */
			chan = add_channel(map, map->map_size + mod->local_off,
					   true);
		}

		/* Save old, overwrite (keep nodeidx) */
		for (size_t h = 0; h < 2; h++) {
			if (!mod->updates_set[h])
				continue;
			mod->orig[h] = chan->half[h];
			mod->orig_cupdate_off[h] = chan->cupdate_off[h];
			chan->half[h] = mod->hc[h];
			chan->half[h].nodeidx = mod->orig[h].nodeidx;
			chan->cupdate_off[h] = 0xFFFFFFFF;
		}
	}
}

void gossmap_remove_localmods(struct gossmap *map,
			      const struct gossmap_localmods *localmods)
{
	size_t n = tal_count(localmods->mods);

	assert(map->local == localmods->local);

	for (size_t i = 0; i < n; i++) {
		const struct localmod *mod = &localmods->mods[i];
		struct gossmap_chan *chan = gossmap_find_chan(map, &mod->scid);

		/* If that's a local channel, remove it now. */
		if (chan->cann_off >= map->map_size) {
			gossmap_remove_chan(map, chan);
		} else {
			/* Restore (keep nodeidx). */
			for (size_t h = 0; h < 2; h++) {
				u32 nodeidx;
				if (!mod->updates_set[h])
					continue;

				nodeidx = chan->half[h].nodeidx;
				chan->half[h] = mod->orig[h];
				chan->half[h].nodeidx = nodeidx;
				chan->cupdate_off[h] = mod->orig_cupdate_off[h];
			}
		}
	}
	map->local = NULL;
}

bool gossmap_refresh(struct gossmap *map, size_t *num_rejected)
{
	off_t len;

	/* You must remove local updates before this. */
	assert(!map->local);

	/* If file has gotten larger, try rereading */
	len = lseek(map->fd, 0, SEEK_END);
	if (len == map->map_size)
		return false;

	if (map->mmap)
		munmap(map->mmap, map->map_size);
	map->map_size = len;
	map->mmap = mmap(NULL, map->map_size, PROT_READ, MAP_SHARED, map->fd, 0);
	if (map->mmap == MAP_FAILED)
		map->mmap = NULL;
	return map_catchup(map, num_rejected);
}

struct gossmap *gossmap_load(const tal_t *ctx, const char *filename,
			     size_t *num_channel_updates_rejected)
{
	map = tal(ctx, struct gossmap);
	map->fname = tal_strdup(map, filename);
	if (load_gossip_store(map, num_channel_updates_rejected))
		tal_add_destructor(map, destroy_map);
	else
		map = tal_free(map);
	return map;
}

void gossmap_node_get_id(const struct gossmap *map,
			 const struct gossmap_node *node,
			 struct node_id *id)
{
	/* We extract nodeid from first channel. */
	int dir;
	struct gossmap_chan *c = gossmap_nth_chan(map, node, 0, &dir);

	map_nodeid(map, c->cann_off + c->plus_scid_off
		   + 8 + PUBKEY_CMPR_LEN*dir, id);
}

bool gossmap_chan_get_capacity(const struct gossmap *map,
			       const struct gossmap_chan *c,
			       struct amount_sat *amount)
{
	struct gossip_hdr ghdr;
	size_t off;
	u16 type;

	/* Fail for local channels */
	if (c->cann_off >= map->map_size)
		return false;

	/* For private, we need to go back WIRE_GOSSIP_STORE_PRIVATE_CHANNEL,
	 * which is 8 (satoshis) + 2 (len) */
	if (c->private) {
		*amount = amount_sat(map_be64(map, c->cann_off - 8 - 2));
		return true;
	}

	/* Skip over this record to next; expect a gossip_store_channel_amount */
	off = c->cann_off - sizeof(ghdr);
	map_copy(map, off, &ghdr, sizeof(ghdr));
	off += sizeof(ghdr) + be16_to_cpu(ghdr.len);

	/* Partial write, this can happen. */
	if (off + sizeof(ghdr) + 2 > map->map_size)
		return false;

	/* Get type of next field. */
	type = map_be16(map, off + sizeof(ghdr));
	if (type != WIRE_GOSSIP_STORE_CHANNEL_AMOUNT)
		return false;

	*amount = amount_sat(map_be64(map, off + sizeof(ghdr) + sizeof(be16)));
	return true;
}

struct gossmap_chan *gossmap_nth_chan(const struct gossmap *map,
				      const struct gossmap_node *node,
				      u32 n,
				      int *which_half)
{
	struct gossmap_chan *chan;

	assert(n < node->num_chans);
	assert(node->chan_idxs[n] < map->num_chan_arr);
	chan = map->chan_arr + node->chan_idxs[n];

	if (which_half) {
		if (chan->half[0].nodeidx == gossmap_node_idx(map, node))
			*which_half = 0;
		else {
			assert(chan->half[1].nodeidx == gossmap_node_idx(map, node));
			*which_half = 1;
		}
	}
	return chan;
}

struct gossmap_node *gossmap_nth_node(const struct gossmap *map,
				      const struct gossmap_chan *chan,
				      int n)
{
	assert(n == 0 || n == 1);

	return map->node_arr + chan->half[n].nodeidx;
}

size_t gossmap_num_nodes(const struct gossmap *map)
{
	return nodeidx_htable_count(map->nodes);
}

static struct gossmap_node *node_iter(const struct gossmap *map, size_t start)
{
	for (size_t i = start; i < map->num_node_arr; i++) {
		if (map->node_arr[i].chan_idxs != NULL)
			return &map->node_arr[i];
	}
	return NULL;
}

struct gossmap_node *gossmap_first_node(const struct gossmap *map)
{
	return node_iter(map, 0);
}

struct gossmap_node *gossmap_next_node(const struct gossmap *map,
				       const struct gossmap_node *prev)
{
	return node_iter(map, prev - map->node_arr + 1);
}

size_t gossmap_num_chans(const struct gossmap *map)
{
	return chanidx_htable_count(map->channels);
}

static struct gossmap_chan *chan_iter(const struct gossmap *map, size_t start)
{
	for (size_t i = start; i < map->num_chan_arr; i++) {
		if (map->chan_arr[i].plus_scid_off != 0)
			return &map->chan_arr[i];
	}
	return NULL;
}

struct gossmap_chan *gossmap_first_chan(const struct gossmap *map)
{
	return chan_iter(map, 0);
}

struct gossmap_chan *gossmap_next_chan(const struct gossmap *map,
				       struct gossmap_chan *prev)
{
	return chan_iter(map, prev - map->chan_arr + 1);
}

bool gossmap_chan_capacity(const struct gossmap_chan *chan,
			   int direction,
			   struct amount_msat amount)
{
	if (amount_msat_less_fp16(amount, chan->half[direction].htlc_min))
		return false;

	if (amount_msat_greater_fp16(amount, chan->half[direction].htlc_max))
		return false;

	return true;
}

/* Get the announcement msg which created this chan */
u8 *gossmap_chan_get_announce(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_chan *c)
{
	u16 len;
	u8 *msg;
	u32 pre_off;

	/* We need to go back to struct gossip_hdr to get len */
	if (c->private)
		pre_off = 2 + 8 + 2 + sizeof(struct gossip_hdr);
	else
		pre_off = sizeof(struct gossip_hdr);
	len = map_be16(map, c->cann_off - pre_off
		       + offsetof(struct gossip_hdr, len));

	msg = tal_arr(ctx, u8, len);
	map_copy(map, c->cann_off, msg, len);
	return msg;
}

/* Get the announcement msg (if any) for this node. */
u8 *gossmap_node_get_announce(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_node *n)
{
	u16 len;
	u8 *msg;

	if (n->nann_off == 0)
		return NULL;

	len = map_be16(map, n->nann_off - sizeof(struct gossip_hdr)
		       + offsetof(struct gossip_hdr, len));
	msg = tal_arr(ctx, u8, len);

	map_copy(map, n->nann_off, msg, len);
	return msg;
}

/* BOLT #7:
 * 1. type: 256 (`channel_announcement`)
 * 2. data:
 *     * [`signature`:`node_signature_1`]
 *     * [`signature`:`node_signature_2`]
 *     * [`signature`:`bitcoin_signature_1`]
 *     * [`signature`:`bitcoin_signature_2`]
 *     * [`u16`:`len`]
 *     * [`len*byte`:`features`]
 *     * [`chain_hash`:`chain_hash`]
 *     * [`short_channel_id`:`short_channel_id`]
 *     * [`point`:`node_id_1`]
 *     * [`point`:`node_id_2`]
 */
int gossmap_chan_get_feature(const struct gossmap *map,
			     const struct gossmap_chan *c,
			     int fbit)
{
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + (64 + 64 + 64 + 64);
	size_t feature_len;

	feature_len = map_be16(map, c->cann_off + feature_len_off);

	return map_feature_test(map, COMPULSORY_FEATURE(fbit),
				c->cann_off + feature_len_off + 2, feature_len);
}

u8 *gossmap_chan_get_features(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_chan *c)
{
	u8 *ret;
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + (64 + 64 + 64 + 64);
	size_t feature_len;

	feature_len = map_be16(map, c->cann_off + feature_len_off);
	ret = tal_arr(ctx, u8, feature_len);

	map_copy(map, c->cann_off + feature_len_off + 2, ret, feature_len);
	return ret;
}

/* BOLT #7:
 * 1. type: 258 (`channel_update`)
 * 2. data:
 *     * [`signature`:`signature`]
 *     * [`chain_hash`:`chain_hash`]
 *     * [`short_channel_id`:`short_channel_id`]
 *     * [`u32`:`timestamp`]
 *     * [`byte`:`message_flags`]
 *     * [`byte`:`channel_flags`]
 *     * [`u16`:`cltv_expiry_delta`]
 *     * [`u64`:`htlc_minimum_msat`]
 *     * [`u32`:`fee_base_msat`]
 *     * [`u32`:`fee_proportional_millionths`]
 *     * [`u64`:`htlc_maximum_msat`]
 */
void gossmap_chan_get_update_details(const struct gossmap *map,
				     const struct gossmap_chan *chan,
				     int dir,
				     u32 *timestamp,
				     u8 *message_flags,
				     u8 *channel_flags,
				     u32 *fee_base_msat,
				     u32 *fee_proportional_millionths,
				     struct amount_msat *htlc_minimum_msat,
				     struct amount_msat *htlc_maximum_msat)
{
	/* Note that first two bytes are message type */
	const size_t scid_off = chan->cupdate_off[dir] + 2 + (64 + 32);
	const size_t timestamp_off = scid_off + 8;
	const size_t message_flags_off = timestamp_off + 4;
	const size_t channel_flags_off = message_flags_off + 1;
	const size_t cltv_expiry_delta_off = channel_flags_off + 1;
	const size_t htlc_minimum_off = cltv_expiry_delta_off + 2;
	const size_t fee_base_off = htlc_minimum_off + 8;
	const size_t fee_prop_off = fee_base_off + 4;
	const size_t htlc_maximum_off = fee_prop_off + 4;

	assert(gossmap_chan_set(chan, dir));

	if (timestamp)
		*timestamp = map_be32(map, timestamp_off);
	if (channel_flags)
		*channel_flags = map_u8(map, channel_flags_off);
	if (message_flags)
		*message_flags = map_u8(map, message_flags_off);
	if (fee_base_msat)
		*fee_base_msat = map_be32(map, fee_base_off);
	if (fee_proportional_millionths)
		*fee_proportional_millionths = map_be32(map, fee_prop_off);
	if (htlc_minimum_msat)
		*htlc_minimum_msat
			= amount_msat(map_be64(map, htlc_minimum_off));
	if (htlc_maximum_msat)
		*htlc_maximum_msat
			= amount_msat(map_be64(map, htlc_maximum_off));
}

/* BOLT #7:
 * 1. type: 257 (`node_announcement`)
 * 2. data:
 *    * [`signature`:`signature`]
 *    * [`u16`:`flen`]
 *    * [`flen*byte`:`features`]
 *    * [`u32`:`timestamp`]
 *    * [`point`:`node_id`]
 *    * [`3*byte`:`rgb_color`]
 *    * [`32*byte`:`alias`]
 *    * [`u16`:`addrlen`]
 *    * [`addrlen*byte`:`addresses`]
 */
int gossmap_node_get_feature(const struct gossmap *map,
			     const struct gossmap_node *n,
			     int fbit)
{
	const size_t feature_len_off = 2 + 64;
	size_t feature_len;

	if (n->nann_off == 0)
		return -1;

	feature_len = map_be16(map, n->nann_off + feature_len_off);

	return map_feature_test(map, COMPULSORY_FEATURE(fbit),
				n->nann_off + feature_len_off + 2, feature_len);
}

u8 *gossmap_node_get_features(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_node *n)
{
	u8 *ret;
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + 64;
	size_t feature_len;

	if (n->nann_off == 0)
		return NULL;

	feature_len = map_be16(map, n->nann_off + feature_len_off);
	ret = tal_arr(ctx, u8, feature_len);

	map_copy(map, n->nann_off + feature_len_off + 2, ret, feature_len);
	return ret;
}
