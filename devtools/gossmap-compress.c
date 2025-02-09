#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/bigsize.h>
#include <common/gossip_store.h>
#include <common/gossmap.h>
#include <common/setup.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wiregen.h>
#if HAVE_ZLIB
#include <zlib.h>
#else
/* Worst... zlib... ever! */
#define gzFile int
#define gzdopen(fd, mode) (fd)
#define gzclose(outf) close(outf)
static int gzread(int fd, void *buf, size_t len)
{
	if (read_all(fd, buf, len))
		return len;
	return 0;
}
static int gzwrite(int fd, const void *buf, size_t len)
{
	if (write_all(fd, buf, len))
		return len;
	return 0;
}
#endif

static unsigned int verbose = 0;

/* All {numbers} are bigsize.
 *
 * <FILE> := <HEADER> <CHANNEL_ENDS> <CAPACITIES> <DISABLEDS> <HTLC_MINS> <HTLC_MAXS> <BASEFEES> <PROPFEES> <DELAYS>
 * <HEADER> := "GOSSMAP_COMPRESSv1\0"
 * <CHANNEL_ENDS> := {channel_count} {start_nodeidx}*{channel_count} {end_nodeidx}*{channel_count}
 *  This describes each attached channel, eg if there are two
 *  channels, node 0 to node 1 and node 0 to node 2, this would be:
 *   2 0 0 1 2
 *
 * <DISABLEDS> := <DISABLED>* {channel_count*2}
 * <DISABLED> := {chanidx}*2+{direction}
 *  Selection of disabled channels and directions, expected to only be a few.  Indexes into the
 *  first channel_ends array.  Terminated by invalid index.
 *
 * <CAPACITIES> := <CAPACITY_TEMPLATES> {channel_count}*{capacity_idx}
 * <CAPACITY_TEMPLATES> := {capacity_count} {channel_count}*{capacity}
 *  This is one satoshi amount per channel.
 *
 * <HTLC_MINS> := <HTLC_MIN_TEMPLATES> {channel_count*2}*{htlc_min_idx}
 * <HTLC_MIN_TEMPLATES> := {htlc_min_count} {htlc_min_count}*{htlc_min}
 *  These templates are all of the same form.  A set of values, followed by
 *  an index into these values for each direction of each channel, in order
 *  1. 0'th channel 1st direction
 *  2. 0'th channel 2nd direction
 *  3. 1'st channel 1st direction
 *  4. 1'st channel 2nd direction
 *
 * <HTLC_MAXS> := <HTLC_MAX_TEMPLATES> {channel_count*2}*{htlc_max_idx}
 *  Note that values 0 and 1 are special: 0 == channel capacity, 1 == 0.99 * channel capacity.
 * <HTLC_MAX_TEMPLATES> := {htlc_max_count} {htlc_max_count}*{htlc_max}
 * <BASEFEES> := <BASEFEE_TEMPLATES> {channel_count*2}*{basefee_idx}
 * <BASEFEE_TEMPLATES> := {basefee_count} {basefee_count}*{basefee}
 * <PROPFEES> := <PROPFEE_TEMPLATES> {channel_count*2}*{propfee_idx}
 * <PROPFEE_TEMPLATES> := {propfee_count} {propfee_count}*{propfee}
 * <DELAYS> := <DELAY_TEMPLATES> {channel_count*2}*{delay_idx}
 * <DELAY_TEMPLATES> := {delay_count} {delay_count}*{delay}
 */

#define GC_HEADER "GOSSMAP_COMPRESSv1"
#define GC_HEADERLEN (sizeof(GC_HEADER))
#define GOSSIP_STORE_VER ((0 << 5) | 14)

/* Backwards, we want larger first */
static int cmp_node_num_chans(struct gossmap_node *const *a,
			      struct gossmap_node *const *b,
			      void *unused)
{
	return (int)(*b)->num_chans - (int)(*a)->num_chans;
}

static void write_bigsize(gzFile outf, u64 val)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, val);
	if (gzwrite(outf, buf, len) == 0)
		err(1, "Writing bigsize");
}

static u64 read_bigsize(gzFile inf)
{
	u64 val;
	u8 buf[BIGSIZE_MAX_LEN];

	if (gzread(inf, buf, 1) != 1)
		errx(1, "Reading bigsize");

	switch (buf[0]) {
	case 0xfd:
		if (gzread(inf, buf+1, 2) != 2)
			errx(1, "Reading bigsize");
		break;
	case 0xfe:
		if (gzread(inf, buf+1, 4) != 4)
			errx(1, "Reading bigsize");
		break;
	case 0xff:
		if (gzread(inf, buf+1, 8) != 8)
			errx(1, "Reading bigsize");
		break;
	}

	if (bigsize_get(buf, sizeof(buf), &val) == 0)
		errx(1, "Bad bigsize");
	return val;
}

static int cmp_u64(const u64 *a,
		   const u64 *b,
		   void *unused)
{
	if (*a > *b)
		return 1;
	else if (*a < *b)
		return -1;
	return 0;
}

static const u64 *deduplicate(const tal_t *ctx, const u64 *vals)
{
	u64 *sorted;
	u64 *dedup;
	size_t n;

	/* Sort and remove dups */
	sorted = tal_dup_talarr(tmpctx, u64, vals);
	asort(sorted, tal_count(sorted), cmp_u64, NULL);

	dedup = tal_arr(ctx, u64, tal_count(sorted));
	n = 0;
	dedup[n++] = sorted[0];
	for (size_t i = 1; i < tal_count(sorted); i++) {
		if (sorted[i] == dedup[n-1])
			continue;
		dedup[n++] = sorted[i];
	}
	tal_resize(&dedup, n);

	return dedup;
}

static size_t find_index(const u64 *template, u64 val)
{
	for (size_t i = 0; i < tal_count(template); i++) {
		if (template[i] == val)
			return i;
	}
	abort();
}

/* All templates are of the same form.  Output all the distinct values, then
 * write out which one is used by each channel */
static void write_template_and_values(gzFile outf, const u64 *vals, const char *what)
{
	/* Sort and remove dups */
	const u64 *template = deduplicate(tmpctx, vals);

	if (verbose)
		printf("%zu unique %s\n", tal_count(template), what);

	assert(tal_count(vals) >= tal_count(template));

	/* Write template. */
	write_bigsize(outf, tal_count(template));
	for (size_t i = 0; i < tal_count(template); i++)
		write_bigsize(outf, template[i]);

	/* Tie every channel into the template.  O(N^2) but who
	 * cares? */
	for (size_t i = 0; i < tal_count(vals); i++) {
		write_bigsize(outf, find_index(template, vals[i]));
	}
}

static void write_bidir_perchan(gzFile outf,
				struct gossmap *gossmap,
				struct gossmap_chan **chans,
				u64 (*get_value)(struct gossmap *,
						 const struct gossmap_chan *,
						 int),
				const char *what)
{
	u64 *vals = tal_arr(tmpctx, u64, tal_count(chans) * 2);

	for (size_t i = 0; i < tal_count(chans); i++) {
		for (size_t dir = 0; dir < 2; dir++) {
			if (chans[i]->half[dir].enabled)
				vals[i*2+dir] = get_value(gossmap, chans[i], dir);
			else
				vals[i*2+dir] = 0;
		}
	}

	write_template_and_values(outf, vals, what);
}

static u64 get_htlc_min(struct gossmap *gossmap,
			const struct gossmap_chan *chan,
			int dir)
{
	struct amount_msat msat;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, NULL, NULL, &msat, NULL);
	return msat.millisatoshis; /* Raw: compressed format */
}

static u64 get_htlc_max(struct gossmap *gossmap,
			const struct gossmap_chan *chan,
			int dir)
{
	struct amount_msat msat, capacity_msat;

	capacity_msat = gossmap_chan_get_capacity(gossmap, chan);
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, NULL, NULL, NULL, &msat);

	/* Special value for the common case of "max_htlc == capacity" */
	if (amount_msat_eq(msat, capacity_msat)) {
		return 0;
	}
	/* Other common case: "max_htlc == 99% capacity" */
	if (amount_msat_scale(&capacity_msat, capacity_msat, 0.99)
	    && amount_msat_eq(msat, capacity_msat)) {
		return 1;
	}
	return msat.millisatoshis; /* Raw: compressed format */
}

static u64 get_basefee(struct gossmap *gossmap,
		       const struct gossmap_chan *chan,
		       int dir)
{
	u32 basefee;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, &basefee, NULL, NULL, NULL);
	return basefee;
}

static u64 get_propfee(struct gossmap *gossmap,
		       const struct gossmap_chan *chan,
		       int dir)
{
	u32 propfee;
	gossmap_chan_get_update_details(gossmap, chan, dir,
					NULL, NULL, NULL, NULL, NULL, &propfee, NULL, NULL);
	return propfee;
}

static u64 get_delay(struct gossmap *gossmap,
		     const struct gossmap_chan *chan,
		     int dir)
{
	return chan->half[dir].delay;
}

static void pubkey_for_node(u64 nodeidx, struct pubkey *key,
			    const struct pubkey **node_ids)
{
	struct secret seckey;

	if (nodeidx < tal_count(node_ids) && node_ids[nodeidx]) {
		*key = *node_ids[nodeidx];
		return;
	}

	memset(&seckey, 1, sizeof(seckey));
	memcpy(&seckey, &nodeidx, sizeof(nodeidx));
	if (!pubkey_from_secret(&seckey, key))
		abort();
}

static void write_msg_to_gstore(int outfd, const u8 *msg TAKES)
{
	struct gossip_hdr hdr;

	hdr.flags = 0;
	hdr.len = cpu_to_be16(tal_bytelen(msg));
	hdr.timestamp = 0;
	hdr.crc = cpu_to_be32(crc32c(0, msg, tal_bytelen(msg)));

	if (!write_all(outfd, &hdr, sizeof(hdr))
	    || !write_all(outfd, msg, tal_bytelen(msg))) {
		err(1, "Writing gossip_store");
	}
	if (taken(msg))
		tal_free(msg);
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
 *     * [`point`:`bitcoin_key_1`]
 *     * [`point`:`bitcoin_key_2`]
 */
static void write_announce(int outfd,
			   size_t node1,
			   size_t node2,
			   u64 capacity,
			   size_t i,
			   const struct pubkey **node_ids)
{
	struct {
		secp256k1_ecdsa_signature sig;
		struct bitcoin_blkid chain_hash;
	} vals;
	u8 *msg;
	struct short_channel_id scid;
	struct pubkey id1, id2;
	struct node_id nodeid1, nodeid2;

	memset(&vals, 0, sizeof(vals));
	pubkey_for_node(node1, &id1, node_ids);
	pubkey_for_node(node2, &id2, node_ids);

	/* Nodes in pubkey order */
	if (pubkey_cmp(&id1, &id2) < 0) {
		node_id_from_pubkey(&nodeid1, &id1);
		node_id_from_pubkey(&nodeid2, &id2);
	} else {
		node_id_from_pubkey(&nodeid1, &id2);
		node_id_from_pubkey(&nodeid2, &id1);
	}
	/* Use i to avoid clashing scids even if two nodes have > 1 channel */
	if (!mk_short_channel_id(&scid, node1, node2, i & 0xFFFF))
		abort();

	msg = towire_channel_announcement(NULL, &vals.sig, &vals.sig, &vals.sig, &vals.sig,
					  NULL, &vals.chain_hash, scid,
					  &nodeid1, &nodeid2,
					  &id1, &id1);
	write_msg_to_gstore(outfd, take(msg));

	msg = towire_gossip_store_channel_amount(NULL, amount_sat(capacity));
	write_msg_to_gstore(outfd, take(msg));
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
static void write_update(int outfd,
			 size_t node1,
			 size_t node2,
			 size_t i,
			 int dir,
			 bool disabled,
			 u64 htlc_min, u64 htlc_max,
			 u64 basefee,
			 u32 propfee,
			 u16 delay,
			 const struct pubkey **node_ids)
{
	struct vals {
		secp256k1_ecdsa_signature sig;
		struct bitcoin_blkid chain_hash;
		u32 timestamp;
	} vals;
	u8 *msg;
	u8 message_flags, channel_flags;
	struct pubkey id1, id2;
	struct short_channel_id scid;

	memset(&vals, 0, sizeof(vals));

	/* Use i to avoid clashing scids even if two nodes have > 1 channel */
	if (!mk_short_channel_id(&scid, node1, node2, i & 0xFFFF))
		abort();

	/* If node ids are backward, dir is reversed */
	pubkey_for_node(node1, &id1, node_ids);
	pubkey_for_node(node2, &id2, node_ids);
	if (pubkey_cmp(&id1, &id2) > 0)
		dir = !dir;

	/* BOLT #7:
	 * The `channel_flags` bitfield is used to indicate the direction of
	 * the channel: it identifies the node that this update originated
	 * from and signals various options concerning the channel. The
	 * following table specifies the meaning of its individual bits:
	 *
	 * | Bit Position  | Name        | Meaning                          |
	 * | ------------- | ----------- | -------------------------------- |
	 * | 0             | `direction` | Direction this update refers to. |
	 * | 1             | `disable`   | Disable the channel.             |
	 *
	 * The `message_flags` bitfield is used to provide additional details about the message:
	 *
	 * | Bit Position  | Name           |
	 * | ------------- | ---------------|
	 * | 0             | `must_be_one`  |
	 * | 1             | `dont_forward` |
	 */
	channel_flags = dir ? 1 : 0;
	if (disabled)
		channel_flags |= 2;
	message_flags = 1;
	msg = towire_channel_update(NULL, &vals.sig, &vals.chain_hash, scid,
				    0, message_flags, channel_flags,
				    delay,
				    amount_msat(htlc_min),
				    basefee, propfee,
				    amount_msat(htlc_max));
	write_msg_to_gstore(outfd, take(msg));
}

static const u64 *read_template(const tal_t *ctx, gzFile inf, const char *what)
{
	size_t count = read_bigsize(inf);
	u64 *template = tal_arr(ctx, u64, count);

	for (size_t i = 0; i < count; i++)
		template[i] = read_bigsize(inf);

	if (verbose)
		printf("%zu unique %s\n", count, what);

	return template;
}

static u64 read_val(gzFile inf, const u64 *template)
{
	size_t idx = read_bigsize(inf);
	assert(idx < tal_count(template));
	return template[idx];
}

static char *opt_add_one(unsigned int *val)
{
	(*val)++;
	return NULL;
}

static char *opt_node(const char *optarg, const struct pubkey ***node_ids)
{
	long num;
	char *endl;
	struct pubkey *pk;

	num = strtol(optarg, &endl, 10);
	if (*endl != '=')
		return tal_fmt(tmpctx, "Must be of form NUMBER '=' NODEID");

	if (tal_count(*node_ids) <= num)
		tal_resizez(node_ids, num + 1);
	(*node_ids)[num] = pk = tal(*node_ids, struct pubkey);

	if (!pubkey_from_hexstr(endl + 1, strlen(endl + 1), pk))
		return tal_fmt(tmpctx, "Invalid node id '%s'", endl + 1);
	return NULL;
}

static const char *get_alias(const tal_t *ctx,
			     const struct gossmap *gossmap,
			     const struct gossmap_node *n)
{
	const u8 *ann = gossmap_node_get_announce(tmpctx, gossmap, n);
	secp256k1_ecdsa_signature signature;
	u8 *features;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *addresses;
	struct tlv_node_ann_tlvs *tlvs;

	if (!fromwire_node_announcement(tmpctx, ann, &signature, &features, &timestamp,
					&node_id, rgb_color, alias, &addresses,
					&tlvs))
		return "";
	return tal_strndup(ctx, (const char *)alias, 32);
}

int main(int argc, char *argv[])
{
	int outfd;
	const struct pubkey **node_ids;
	bool print_nodes = false;

	common_setup(argv[0]);
	setup_locale();

	node_ids = tal_arr(tmpctx, const struct pubkey *, 0);
	opt_register_noarg("--verbose|-v", opt_add_one, &verbose,
			   "Print details (each additional gives more!).");
	opt_register_arg("--node-map=num=<nodeid>", opt_node, NULL, &node_ids,
			   "Map node num to <nodeid> (decompress only)");
	opt_register_noarg("--output-node-map", opt_set_bool, &print_nodes,
			   "Output nodenumber:nodeid:alias for each node (compress only)");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[decompress|compress] infile outfile\n"
			   "Compress or decompress a gossmap file",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 4)
		opt_usage_exit_fail("Needs 4 arguments");

	outfd = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (outfd < 0)
		opt_usage_exit_fail(tal_fmt(tmpctx, "Cannot open %s for writing: %s",
					    argv[3], strerror(errno)));

	if (streq(argv[1], "compress")) {
		struct gossmap_node **nodes, *n;
		size_t *node_to_compr_idx;
		size_t node_count, channel_count;
		struct gossmap_chan **chans, *c;
		bool *dirs;
		gzFile outf = gzdopen(outfd, "wb9");

		struct gossmap *gossmap = gossmap_load(tmpctx, argv[2], NULL);
		if (!gossmap)
			opt_usage_exit_fail(tal_fmt(tmpctx, "Cannot open %s for reading: %s",
						    argv[2], strerror(errno)));

		nodes = tal_arr(gossmap, struct gossmap_node *, gossmap_max_node_idx(gossmap));
		for (node_count = 0, n = gossmap_first_node(gossmap);
		     n;
		     n = gossmap_next_node(gossmap, n), node_count++) {
			nodes[node_count] = n;
		}
		tal_resize(&nodes, node_count);
		if (verbose)
			printf("%zu nodes\n", node_count);

		/* nodes with most channels go first */
		asort(nodes, tal_count(nodes), cmp_node_num_chans, NULL);

		/* Create map of gossmap index to compression index */
		node_to_compr_idx = tal_arr(nodes, size_t, gossmap_max_node_idx(gossmap));
		for (size_t i = 0; i < tal_count(nodes); i++) {
			node_to_compr_idx[gossmap_node_idx(gossmap, nodes[i])] = i;
			if (print_nodes) {
				struct node_id node_id;
				gossmap_node_get_id(gossmap, nodes[i], &node_id);

				printf("%zu:%s:%s\n",
				       i,
				       fmt_node_id(tmpctx, &node_id),
				       get_alias(tmpctx, gossmap, nodes[i]));
			}
		}

		if (gzwrite(outf, GC_HEADER, GC_HEADERLEN) == 0)
			err(1, "Writing header");

		/* Now, output channels.  First get exact count. */
		for (channel_count = 0, c = gossmap_first_chan(gossmap);
		     c;
		     c = gossmap_next_chan(gossmap, c)) {
			channel_count++;
		}

		if (verbose)
			printf("%zu channels\n", channel_count);
		chans = tal_arr(gossmap, struct gossmap_chan *, channel_count);
		dirs = tal_arr(gossmap, bool, channel_count);

		/*  * <CHANNEL_ENDS> := {channel_count} {start_nodeidx}*{channel_count} {end_nodeidx}*{channel_count} */
		write_bigsize(outf, channel_count);
		size_t chanidx = 0;
		/* We iterate nodes to get to channels.  This gives us nicer ordering for compression */
		for (size_t i = 0; i < tal_count(nodes); i++) {
			n = nodes[i];
			for (size_t j = 0; j < n->num_chans; j++) {
				const struct gossmap_node *peer;
				int dir;
				c = gossmap_nth_chan(gossmap, n, j, &dir);

				peer = gossmap_nth_node(gossmap, c, !dir);
				/* Don't write if peer already wrote it! */
				/* FIXME: What about self-channels? */
				if (node_to_compr_idx[gossmap_node_idx(gossmap, peer)] < i)
					continue;

				write_bigsize(outf, node_to_compr_idx[gossmap_node_idx(gossmap, n)]);

				assert(chanidx < channel_count);
				dirs[chanidx] = dir;
				chans[chanidx] = c;
				chanidx++;
			}
		}
		assert(chanidx == channel_count);

		/* Now write out the other ends of the channels */
		for (size_t i = 0; i < channel_count; i++) {
			const struct gossmap_node *peer;

			peer = gossmap_nth_node(gossmap, chans[i], !dirs[i]);
			write_bigsize(outf, node_to_compr_idx[gossmap_node_idx(gossmap, peer)]);
		}

		/* <DISABLEDS> := <DISABLED>* {channel_count*2} */
		/* <DISABLED> := {chanidx}*2+{direction} */
		size_t num_disabled = 0;
		size_t num_unknown = 0;
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				if (chans[i]->cupdate_off[dir] == 0)
					num_unknown++;
				if (!chans[i]->half[dir].enabled) {
					write_bigsize(outf, i * 2 + dir);
					num_disabled++;
				}
			}
		}
		write_bigsize(outf, channel_count * 2);
		if (verbose)
			printf("%zu disabled channels (%zu no update)\n", num_disabled, num_unknown);

		/* <CAPACITIES> := <CAPACITY_TEMPLATES> {channel_count}*{capacity_idx} */
		/* <CAPACITY_TEMPLATES> := {capacity_count} {capacity_count}*{capacity} */
		u64 *vals = tal_arr(chans, u64, channel_count);
		for (size_t i = 0; i < channel_count; i++) {
			struct amount_msat cap;
			cap = gossmap_chan_get_capacity(gossmap, chans[i]);
			vals[i] = cap.millisatoshis / 1000; /* Raw: compression format */
		}
		write_template_and_values(outf, vals, "capacities");

		/* These are all of same form: one entry per direction per channel */
		/* <HTLC_MINS> := <HTLC_MIN_TEMPLATES> {channel_count}*{htlc_min_idx} */
		/* <HTLC_MIN_TEMPLATES> := {htlc_min_count} {htlc_min_count}*{htlc_min} */
		/* <HTLC_MAXS> := <HTLC_MAX_TEMPLATES> {channel_count}*{htlc_max_idx} */
		/* <HTLC_MAX_TEMPLATES> := {htlc_max_count} {htlc_max_count}*{htlc_max} */
		/* <BASEFEES> := <BASEFEE_TEMPLATES> {channel_count}*{basefee_idx} */
		/* <BASEFEE_TEMPLATES> := {basefee_count} {basefee_count}*{basefee} */
		/* <PROPFEES> := <PROPFEE_TEMPLATES> {channel_count}*{propfee_idx} */
		/* <PROPFEE_TEMPLATES> := {propfee_count} {propfee_count}*{propfee} */
		/* <DELAYS> := <DELAY_TEMPLATES> {channel_count}*{delay_idx} */
		/* <DELAY_TEMPLATES> := {delay_count} {delay_count}*{delay} */
		write_bidir_perchan(outf, gossmap, chans, get_htlc_min, "htlc_min");
		write_bidir_perchan(outf, gossmap, chans, get_htlc_max, "htlc_max");
		write_bidir_perchan(outf, gossmap, chans, get_basefee, "basefee");
		write_bidir_perchan(outf, gossmap, chans, get_propfee, "propfee");
		write_bidir_perchan(outf, gossmap, chans, get_delay, "delay");
		gzclose(outf);
	} else if (streq(argv[1], "decompress")) {
		char hdr[GC_HEADERLEN];
		size_t channel_count, chanidx;
		const u64 *template;
		struct fakechan {
			size_t node1, node2;
			u64 capacity;
			struct halffake {
				u64 htlc_min, htlc_max;
				u32 basefee, propfee;
				u32 delay;
				bool disabled;
			} half[2];
		} *chans;
		const u8 version = GOSSIP_STORE_VER;
		size_t disabled_count, node_limit;
		gzFile inf = gzopen(argv[2], "rb");

		if (!inf)
			opt_usage_exit_fail(tal_fmt(tmpctx, "Cannot open %s for reading: %s",
						    argv[2], strerror(errno)));

		if (gzread(inf, hdr, sizeof(hdr)) != sizeof(hdr)
		    || !memeq(hdr, sizeof(hdr), GC_HEADER, GC_HEADERLEN))
			errx(1, "Not a valid compressed gossmap header");
		channel_count = read_bigsize(inf);
		if (verbose)
			printf("%zu channels\n", channel_count);
		chans = tal_arrz(tmpctx, struct fakechan, channel_count);

		node_limit = 0;
		for (size_t i = 0; i < channel_count; i++) {
			chans[i].node1 = read_bigsize(inf);
			if (chans[i].node1 >= node_limit)
				node_limit = chans[i].node1 + 1;
		}
		for (size_t i = 0; i < channel_count; i++) {
			chans[i].node2 = read_bigsize(inf);
			if (chans[i].node2 >= node_limit)
				node_limit = chans[i].node2 + 1;
		}

		/* Useful so they can map their ids back to node ids. */
		for (size_t i = 0; i < node_limit; i++) {
			struct pubkey node_id;
			pubkey_for_node(i, &node_id, node_ids);
			printf("%s\n", fmt_pubkey(tmpctx, &node_id));
		}

		if (verbose >= 2) {
			for (size_t i = 0; i < channel_count; i++) {
				struct pubkey id1, id2;
				pubkey_for_node(chans[i].node1, &id1, node_ids);
				pubkey_for_node(chans[i].node2, &id2, node_ids);
				printf("Channel %zu: %s -> %s\n",
				       i,
				       fmt_pubkey(tmpctx, &id1),
				       fmt_pubkey(tmpctx, &id2));
			}
		}

		disabled_count = 0;
		while ((chanidx = read_bigsize(inf)) < channel_count*2) {
			disabled_count++;
			chans[chanidx/2].half[chanidx%2].disabled = true;
		}
		if (verbose)
			printf("%zu disabled\n", disabled_count);

		template = read_template(tmpctx, inf, "capacities");
		for (size_t i = 0; i < channel_count; i++)
			chans[i].capacity = read_val(inf, template);

		template = read_template(tmpctx, inf, "htlc_min");
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				chans[i].half[dir].htlc_min = read_val(inf, template);
			}
		}
		template = read_template(tmpctx, inf, "htlc_max");
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				u64 v = read_val(inf, template);
				if (v == 0)
					v = chans[i].capacity;
				else if (v == 1)
					v = chans[i].capacity * 0.99;
				chans[i].half[dir].htlc_max = v;
			}
		}
		template = read_template(tmpctx, inf, "basefee");
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				chans[i].half[dir].basefee = read_val(inf, template);
			}
		}
		template = read_template(tmpctx, inf, "propfee");
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				chans[i].half[dir].propfee = read_val(inf, template);
			}
		}
		template = read_template(tmpctx, inf, "delay");
		for (size_t i = 0; i < channel_count; i++) {
			for (size_t dir = 0; dir < 2; dir++) {
				chans[i].half[dir].delay = read_val(inf, template);
			}
		}

		/* Now write out gossmap */
		if (write(outfd, &version, 1) != 1)
			err(1, "Failed to write output");
		for (size_t i = 0; i < channel_count; i++) {
			write_announce(outfd,
				       chans[i].node1,
				       chans[i].node2,
				       chans[i].capacity,
				       i, node_ids);
			for (size_t dir = 0; dir < 2; dir++) {
				write_update(outfd,
					     chans[i].node1, chans[i].node2, i, dir,
					     chans[i].half[dir].disabled,
					     chans[i].half[dir].htlc_min,
					     chans[i].half[dir].htlc_max,
					     chans[i].half[dir].basefee,
					     chans[i].half[dir].propfee,
					     chans[i].half[dir].delay,
					     node_ids);
			}
		}
		gzclose(inf);
	} else
		opt_usage_and_exit("Unknown command");

	close(outfd);
	common_shutdown();
}
