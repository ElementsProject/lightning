#include <assert.h>
#include <ccan/bitops/bitops.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/htable/htable_type.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/gossip_store.h>
#include <common/gossmap.h>
#include <common/node_id.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/peer_wire.h>

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
	int st_dev, st_ino;
	const char *fname;

	/* The memory map of the file: u8 for arithmetic portability */
	u8 *mmap;
	/* map_end is where we read to so far, map_size is total size */
	size_t map_end, map_size;

	/* Map of node id -> node */
	struct nodeidx_htable nodes;

	/* Map of short_channel_id id -> channel */
	struct chanidx_htable channels;

	/* Array of nodes, so we can use simple index. */
	struct gossmap_node *node_arr;

	/* Array of chans, so we can use simple index */
	struct gossmap_chan *chan_arr;

	/* Linked list of freed ones, if any. */
	u32 freed_nodes, freed_chans;
};

/* Accessors for the gossmap */
static void map_copy(const struct gossmap *map, size_t offset,
		     void *dst, size_t len)
{
	assert(offset < map->map_size);
	assert(offset + len <= map->map_size);
	if (map->mmap)
		memcpy(dst, map->mmap + offset, len);
	else {
		/* Yeah, we'll crash on I/O errors. */
		if (pread(map->fd, dst, len, offset) != len)
			abort();
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

static bool map_feature_set(const struct gossmap *map, int bit,
			    size_t offset, size_t len)
{
	size_t bytenum = bit / 8;

	if (bytenum >= len)
		return false;

	/* Note reversed! */
	return map_u8(map, offset + len - 1 - bytenum) & (1 << (bit % 8));
}

/* These values can change across calls to gossmap_check. */
u32 gossmap_max_node_idx(const struct gossmap *map)
{
	return tal_count(map->node_arr);
}

u32 gossmap_max_chan_idx(const struct gossmap *map)
{
	return tal_count(map->chan_arr);
}

/* Each channel has a unique (low) index. */
u32 gossmap_node_idx(const struct gossmap *map, const struct gossmap_node *node)
{
	assert(node - map->node_arr < tal_count(map->node_arr));
	return node - map->node_arr;
}

u32 gossmap_chan_idx(const struct gossmap *map, const struct gossmap_chan *chan)
{
	assert(chan - map->chan_arr < tal_count(map->chan_arr));
	return chan - map->chan_arr;
}

/* htable can't handle NULL values, so we add 1 */
static struct gossmap_chan *ptrint2chan(const ptrint_t *pidx)
{
	return map->chan_arr + ptr2int(pidx) - 1;
}

static ptrint_t *chan2ptrint(const struct gossmap_chan *chan)
{
	return int2ptr(chan - map->chan_arr + 1);
}

static struct gossmap_node *ptrint2node(const ptrint_t *pidx)
{
	return map->node_arr + ptr2int(pidx) - 1;
}

static ptrint_t *node2ptrint(const struct gossmap_node *node)
{
	return int2ptr(node - map->node_arr + 1);
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
	ptrint_t *pi = nodeidx_htable_get(&map->nodes, *id);
	if (pi)
		return ptrint2node(pi);
	return NULL;
}

struct gossmap_chan *gossmap_find_chan(const struct gossmap *map,
				       const struct short_channel_id *scid)
{
	ptrint_t *pi = chanidx_htable_get(&map->channels, *scid);
	if (pi)
		return ptrint2chan(pi);
	return NULL;
}

static fp16_t u64_to_fp16(u64 val, bool round_up)
{
	u16 mantissa_bits, mantissa, exponent;

	if (val == 0)
		return 0;

	/* How many bits do we need to represent mantissa? */
	mantissa_bits = bitops_hs64(val) + 1;

	/* We only have 11 bits, so if we need more, we will round. */
	if (mantissa_bits > 11) {
		exponent = mantissa_bits - 11;
		mantissa = (val >> exponent);
		/* If we're losing bits here, we're rounding down */
		if (round_up && (val & ((1ULL << exponent)-1))) {
			mantissa++;
			if (mantissa == (1 << 11)) {
				mantissa >>= 1;
				exponent++;
			}
		}
		/* huge number? Make it max. */
		if (exponent >= 32) {
			exponent = 31;
			mantissa = (1 << 11)-1;
		}
	} else {
		exponent = 0;
		mantissa = val;
	}

	assert((mantissa >> 11) == 0);
	return (exponent << 11) | mantissa;
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
	if (!nodeidx_htable_del(&map->nodes, node2ptrint(node)))
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
		chan_arr[i].scid_off = 0;
	}
	chan_arr[i].cann_off = UINT_MAX;
	chan_arr[i].scid_off = 0;
	return start;
}

/* Freelist links through scid of unused entries. */
static struct gossmap_chan *next_free_chan(struct gossmap *map)
{
	size_t f;

	if (map->freed_chans == UINT_MAX) {
		/* Double in size, add second half to free list */
		size_t n = tal_count(map->chan_arr);
		tal_resize(&map->chan_arr, n * 2);
		map->freed_chans = init_chan_arr(map->chan_arr, n);
	}

	f = map->freed_chans;
	map->freed_chans = map->chan_arr[f].cann_off;
	return &map->chan_arr[f];
}

static struct gossmap_chan *new_channel(struct gossmap *map,
					u32 cannounce_off,
					u32 scid_off,
					u32 n1idx, u32 n2idx)
{
	struct gossmap_chan *chan = next_free_chan(map);

	chan->cann_off = cannounce_off;
	chan->scid_off = scid_off;
	memset(chan->half, 0, sizeof(chan->half));
	chan->half[0].nodeidx = n1idx;
	chan->half[1].nodeidx = n2idx;
	node_add_channel(map->node_arr + n1idx, gossmap_chan_idx(map, chan));
	node_add_channel(map->node_arr + n2idx, gossmap_chan_idx(map, chan));
	chanidx_htable_add(&map->channels, chan2ptrint(chan));

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
	if (!chanidx_htable_del(&map->channels, chan2ptrint(chan)))
		abort();
	remove_chan_from_node(map, gossmap_nth_node(map, chan, 0), chanidx);
	remove_chan_from_node(map, gossmap_nth_node(map, chan, 1), chanidx);
	chan->cann_off = map->freed_chans;
	chan->scid_off = 0;
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
static void add_channel(struct gossmap *map, size_t cannounce_off)
{
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + (64 + 64 + 64 + 64);
	size_t feature_len;
	size_t scid_off;
	struct node_id node_id[2];
	struct gossmap_node *n[2];
	u32 nidx[2];

	feature_len = map_be16(map, cannounce_off + feature_len_off);
	scid_off = cannounce_off + feature_len_off + 2 + feature_len + 32;

	map_nodeid(map, scid_off + 8, &node_id[0]);
	map_nodeid(map, scid_off + 8 + PUBKEY_CMPR_LEN, &node_id[1]);

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

	new_channel(map, cannounce_off, scid_off, nidx[0], nidx[1]);

	/* Now we have a channel, we can add nodes to htable */
	if (!n[0])
		nodeidx_htable_add(&map->nodes,
				   node2ptrint(map->node_arr + nidx[0]));
	if (!n[1])
		nodeidx_htable_add(&map->nodes,
				   node2ptrint(map->node_arr + nidx[1]));
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
 *     * [`u64`:`htlc_maximum_msat`] (option_channel_htlc_max)
 */
static void update_channel(struct gossmap *map, size_t cupdate_off)
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

	scid.u64 = map_be64(map, scid_off);
	chan = gossmap_find_chan(map, &scid);
	if (!chan)
		errx(1, "update for channel %s not found!",
		     type_to_string(tmpctx, struct short_channel_id, &scid));

	hc.htlc_min = u64_to_fp16(map_be64(map, htlc_minimum_off), true);
	/* I checked my node: 60189 of 62358 channel_update have
	 * htlc_maximum_msat, so we don't bother setting the rest to the
	 * channel size (which we don't even read from the gossip_store, let
	 * alone give up precious bytes to remember) */
	if (map_u8(map, message_flags_off) & 1)
		hc.htlc_max
			= u64_to_fp16(map_be64(map, htlc_maximum_off), false);
	else
		hc.htlc_max = 0xFFFF;
	hc.base_fee = map_be32(map, fee_base_off);
	hc.proportional_fee = map_be32(map, fee_prop_off);
	hc.delay = map_be16(map, cltv_expiry_delta_off);

	/* Check they fit */
	if (hc.base_fee != map_be32(map, fee_base_off)
	    || hc.proportional_fee != map_be32(map, fee_prop_off)
	    || hc.delay != map_be16(map, cltv_expiry_delta_off)) {
		warnx("channel_update %s ignored: fee %u/%u cltv %u too large",
		      type_to_string(tmpctx, struct short_channel_id, &scid),
		      map_be32(map, fee_base_off),
		      map_be32(map, fee_prop_off),
		      map_be16(map, cltv_expiry_delta_off));
		return;
	}

	chanflags = map_u8(map, channel_flags_off);
	hc.enabled = !(chanflags & 2);
	/* Preserve this */
	hc.nodeidx = chan->half[chanflags & 1].nodeidx;
	chan->half[chanflags & 1] = hc;
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
	scid.u64 = map_be64(map, c->scid_off);

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
	n = gossmap_find_node(map, &id);
	n->nann_off = nann_off;
}

static bool map_catchup(struct gossmap *map)
{
	size_t reclen;
	bool changed = false;

	for (; map->map_end + sizeof(struct gossip_hdr) < map->map_size;
	     map->map_end += reclen) {
		struct gossip_hdr ghdr;
		size_t off;
		u16 type;

		map_copy(map, map->map_end, &ghdr, sizeof(ghdr));
		reclen = (be32_to_cpu(ghdr.len)
			  & ~(GOSSIP_STORE_LEN_DELETED_BIT|
			      GOSSIP_STORE_LEN_PUSH_BIT))
			+ sizeof(ghdr);

		if (be32_to_cpu(ghdr.len) & GOSSIP_STORE_LEN_DELETED_BIT)
			continue;

		/* Partial write, this can happen. */
		if (map->map_end + reclen > map->map_size)
			break;

		off = map->map_end + sizeof(ghdr);
		type = map_be16(map, off);
		if (type == WIRE_CHANNEL_ANNOUNCEMENT)
			add_channel(map, off);
		else if (type == WIRE_CHANNEL_UPDATE)
			update_channel(map, off);
		else if (type == WIRE_GOSSIP_STORE_DELETE_CHAN)
			remove_channel_by_deletemsg(map, off);
		else if (type == WIRE_NODE_ANNOUNCEMENT)
			node_announcement(map, off);
		else
			continue;

		changed = true;
	}

	return changed;
}

static bool load_gossip_store(struct gossmap *map)
{
	struct stat st;

	map->fd = open(map->fname, O_RDONLY);
	if (map->fd < 0)
		return false;

	fstat(map->fd, &st);
	map->st_dev = st.st_dev;
	map->st_ino = st.st_ino;
	map->map_size = st.st_size;
	/* If this fails, we fall back to read */
	map->mmap = mmap(NULL, map->map_size, PROT_READ, MAP_SHARED, map->fd, 0);
	if (map->mmap == MAP_FAILED)
		map->mmap = NULL;

	if (map_u8(map, 0) != GOSSIP_STORE_VERSION) {
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
	chanidx_htable_init_sized(&map->channels, st.st_size / 750 / 2);
	nodeidx_htable_init_sized(&map->nodes, st.st_size / 2500 / 2);

	map->chan_arr = tal_arr(map, struct gossmap_chan, st.st_size / 750 / 2 + 1);
	map->freed_chans = init_chan_arr(map->chan_arr, 0);
	map->node_arr = tal_arr(map, struct gossmap_node, st.st_size / 2500 / 2 + 1);
	map->freed_nodes = init_node_arr(map->node_arr, 0);

	map->map_end = 1;
	map_catchup(map);
	return true;
}

static void destroy_map(struct gossmap *map)
{
	if (map->mmap)
		munmap(map->mmap, map->map_size);
	chanidx_htable_clear(&map->channels);
	nodeidx_htable_clear(&map->nodes);

	for (size_t i = 0; i < tal_count(map->node_arr); i++)
		free(map->node_arr[i].chan_idxs);
}

bool gossmap_refresh(struct gossmap *map)
{
	struct stat st;

	/* If file has changed, move to it. */
	if (stat(map->fname, &st) != 0)
		err(1, "statting %s", map->fname);

	if (map->st_ino != st.st_ino || map->st_dev != st.st_dev) {
		destroy_map(map);
		tal_free(map->chan_arr);
		tal_free(map->node_arr);
		if (!load_gossip_store(map))
			err(1, "reloading %s", map->fname);
		return true;
	}

	/* If file has gotten larger, try rereading */
	if (st.st_size == map->map_size)
		return false;

	if (map->mmap)
		munmap(map->mmap, map->map_size);
	map->map_size = st.st_size;
	map->mmap = mmap(NULL, map->map_size, PROT_READ, MAP_SHARED, map->fd, 0);
	if (map->mmap == MAP_FAILED)
		map->mmap = NULL;
	return map_catchup(map);
}

struct gossmap *gossmap_load(const tal_t *ctx, const char *filename)
{
	map = tal(ctx, struct gossmap);
	map->fname = tal_strdup(map, filename);
	if (load_gossip_store(map))
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

	map_nodeid(map, c->scid_off + 8 + PUBKEY_CMPR_LEN*dir, id);
}

struct gossmap_chan *gossmap_nth_chan(const struct gossmap *map,
				      const struct gossmap_node *node,
				      u32 n,
				      int *which_half)
{
	struct gossmap_chan *chan;

	assert(n < node->num_chans);
	assert(node->chan_idxs[n] < tal_count(map->chan_arr));
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
	return nodeidx_htable_count(&map->nodes);
}

static struct gossmap_node *node_iter(const struct gossmap *map, size_t start)
{
	for (size_t i = start; i < tal_count(map->node_arr); i++) {
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
	return chanidx_htable_count(&map->channels);
}

static struct gossmap_chan *chan_iter(const struct gossmap *map, size_t start)
{
	for (size_t i = start; i < tal_count(map->chan_arr); i++) {
		if (map->chan_arr[i].scid_off != 0)
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
	if (amount.millisatoshis /* Raw: fp16 compare */
	    < fp16_to_u64(chan->half[direction].htlc_min))
		return false;

	if (amount.millisatoshis /* Raw: fp16 compare */
	    > fp16_to_u64(chan->half[direction].htlc_max))
		return false;

	return true;
}

/* Get the announcement msg which created this chan */
u8 *gossmap_chan_get_announce(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_chan *c)
{
	u16 len = map_be16(map, c->cann_off);
	u8 *msg = tal_arr(ctx, u8, len);

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

	len = map_be16(map, n->nann_off);
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
int gossmap_chan_has_feature(const struct gossmap *map,
			     const struct gossmap_chan *c,
			     int fbit)
{
	/* Note that first two bytes are message type */
	const size_t feature_len_off = 2 + (64 + 64 + 64 + 64);
	size_t feature_len;

	feature_len = map_be16(map, c->cann_off + feature_len_off);

	if (map_feature_set(map, OPTIONAL_FEATURE(fbit),
			    c->cann_off + feature_len_off + 2, feature_len))
		return OPTIONAL_FEATURE(fbit);
	if (map_feature_set(map, COMPULSORY_FEATURE(fbit),
			    c->cann_off + feature_len_off + 2, feature_len))
		return COMPULSORY_FEATURE(fbit);
	return -1;
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
int gossmap_node_has_feature(const struct gossmap *map,
			     const struct gossmap_node *n,
			     int fbit)
{
	const size_t feature_len_off = 2 + 64;
	size_t feature_len;

	if (n->nann_off == 0)
		return -1;

	feature_len = map_be16(map, n->nann_off + feature_len_off);

	if (map_feature_set(map, OPTIONAL_FEATURE(fbit),
			    n->nann_off + feature_len_off + 2, feature_len))
		return OPTIONAL_FEATURE(fbit);
	if (map_feature_set(map, COMPULSORY_FEATURE(fbit),
			    n->nann_off + feature_len_off + 2, feature_len))
		return COMPULSORY_FEATURE(fbit);
	return -1;
}
